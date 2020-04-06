
"""

tsd-file-api
------------

A multi-tenent API for uploading and downloading files and JSON data,
designed for the University of Oslo's Services for Sensitive Data (TSD).

"""

import base64
import logging
import os
import pwd
import datetime
import hashlib
import subprocess
import stat
import shutil
import fileinput
import json
import re
import sqlite3
import time

from uuid import uuid4
from sys import argv
from collections import OrderedDict

import yaml
import magic
import tornado.queues
import libnacl.sealed
import libnacl.public

import tornado.log
from pandas import DataFrame
from termcolor import colored
from tornado.escape import json_decode, url_unescape, url_escape
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from tornado.ioloop import IOLoop
from tornado.options import parse_command_line, define, options
from tornado.web import Application, RequestHandler, stream_request_body, \
                        HTTPError, MissingArgumentError

from tsdfileapi.auth import process_access_token
from tsdfileapi.utils import call_request_hook, sns_dir, \
                  check_filename, _IS_VALID_UUID, \
                  md5sum, tenant_from_url, create_cluster_dir_if_not_exists, \
                  move_data_to_folder
from tsdfileapi.db import sqlite_init, SqliteBackend, postgres_init, PostgresBackend
from tsdfileapi.resumables import SerialResumable
from tsdfileapi.pgp import _import_keys
from tsdfileapi.rmq import PikaClient


_RW______ = stat.S_IREAD | stat.S_IWRITE
_RW_RW___ = _RW______ | stat.S_IRGRP | stat.S_IWGRP
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')


def read_config(filename):
    with open(filename) as f:
        conf = yaml.load(f, Loader=yaml.Loader)
    return conf


def set_config():
    try:
        _config = read_config(argv[1])
    except IndexError as e:
        print(colored('Missing config file, running with default setup', 'yellow'))
        print(colored('WARNING: do _not_ do this in production', 'red'))
        from tsdfileapi.defaults import _config
        from tsdfileapi.tokens import tkn
        for k,v in _config.items():
            print(colored(f'{k}:', 'yellow'), colored(f'{v}', 'magenta'))
        print(colored('JWT token for dev purposes:', 'cyan'))
        print(tkn(
            _config['jwt_test_secret'],
            exp=3600,
            role='admin_user',
            tenant='p11',
            user='p11-test')
        )
    try:
        if argv[2].startswith('--port:'):
            port = argv[2].split(':')[1]
            define('port', int(port))
        else:
            define('port', _config['port'])
    except Exception:
        define('port', _config['port'])
    define('config', _config)
    define('debug', _config['debug'])
    define('api_user', _config['api_user'])
    define('check_tenant', _config['token_check_tenant'])
    define('check_exp', _config['token_check_exp'])
    define('start_chars', _config['disallowed_start_chars'])
    define('requestor_claim_name', _config['requestor_claim_name'])
    define('tenant_claim_name', _config['tenant_claim_name'])
    define('tenant_string_pattern', _config['tenant_string_pattern'])
    define('export_chunk_size', _config['export_chunk_size'])
    define('valid_tenant', re.compile(r'{}'.format(_config['valid_tenant_regex'])))
    define('max_body_size', _config['max_body_size'])
    define('default_file_owner', _config['default_file_owner'])
    define('create_tenant_dir', _config['create_tenant_dir'])
    define('jwt_secret', _config['jwt_secret'] if 'jwt_secret' in _config.keys() else None)
    define('max_nacl_chunksize', 500000) # don't want more than 0.5MB
    define('sealed_box', libnacl.sealed.SealedBox(
            libnacl.public.SecretKey(
                base64.b64decode(_config['nacl_public']['private'])
            )
        )
    )
    define('rabbitmq', _config.get('rabbitmq', {}))
    define('maintenance_mode_enabled', False)
    options.logging = _config.get('log_level', 'info')

set_config()


class AuthRequestHandler(RequestHandler):


    """
    All RequestHandler(s), with the exception of the HealthCheckHandler
    inherit from this one, giving them access to the
    process_token_and_extract_claims method.

    The purpose of this method is to allow a measure of authentication
    and authorization - just enough to be able to enforce access control
    on a per request basis, where necessary.

    When called, the method will set the following properties:

        self.jwt
        self.tenant
        self.claims
        self.requestor

    Subsequent request handlers (HTTP method implementations), use these properties
    for request processing, and enforcement of access control where needed.
    The API can be configured to check whether the tenant identifier in the URL
    matches the tenant identifier in the claims. It can also be configured
    to check the token expiry. These are not mandatory.

    To decide what is right for your use case read the module level docstring
    about the different endpoints, and use cases underpinning their design
    and implementation.

    """

    def process_token_and_extract_claims(
            self,
            check_tenant=options.check_tenant,
            check_exp=options.check_exp,
            tenant_claim_name=options.tenant_claim_name,
            verify_with_secret=options.jwt_secret):
        """
        When performing requests against the API, JWT access tokens are presented
        in the Authorization header of the HTTP request as a Bearer token. Before
        the body of each request is processed this method is called in 'prepare'.

        The process_access_token method will:
            - extract claims from the JWT
            - optionally check:
                - consistent tenant access
                - token expiry
                - signature, if provided with a secret

        The latter checks are OPTIONAL since they SHOULD already have been
        performed by an authorization server _before_ the request is handled here.

        Returns
        -------
        bool or dict

        """
        self.status = None
        try:
            try:
                auth_header = self.request.headers['Authorization']
            except (KeyError, UnboundLocalError) as e:
                self.message = 'Missing authorization header'
                logging.error(self.message)
                self.set_status(400)
                raise Exception('Authorization not possible: missing header')
            try:
                self.jwt = auth_header.split(' ')[1]
            except IndexError as e:
                self.message = 'Malformed authorization header'
                logging.error(self.message)
                self.set_status(400)
                raise Exception('Authorization not possible: malformed header')
            try:
                tenant = tenant_from_url(self.request.uri)
                assert options.valid_tenant.match(tenant)
                self.tenant = tenant
            except AssertionError as e:
                logging.error(e.message)
                logging.error('tenant invalid')
                self.set_status(400)
                raise e
            try:
                authnz = process_access_token(
                    auth_header,
                    tenant,
                    check_tenant,
                    check_exp,
                    tenant_claim_name,
                    verify_with_secret
                )
                self.claims = authnz['claims']
                self.requestor = self.claims[options.requestor_claim_name]
                if not authnz['status']:
                    self.set_status(401)
                    raise Exception('JWT verification failed')
                elif authnz['status']:
                    return authnz
            except Exception as e:
                self.message = authnz['reason']
                logging.error(e)
                self.set_status(401)
                raise Exception('Authorization failed')
        except Exception as e:
            if not self.status:
                self.set_status(401)
            raise Exception

    def get_group_info(self, tenant, group_config, authnz_status):
        """
        Set intended group owner of resource, and extract memberships
        of the requestor, falling back to configured defaults, depending
        on the backend.

        """
        if not group_config['enabled']:
            return group_config['default_url_group'], group_config['default_memberships']
        try:
            group_name = url_unescape(self.get_query_argument('group'))
        except HTTPError as e:
            # first check if it is in the url
            found = re.sub(r'/v1/.+/(p[0-9]+-[a-zA-Z0-9]+-group).*', r'\1', self.request.uri)
            if found == self.request.uri:
                # then it is not there, so we need to use the default
                default_url_group = group_config['default_url_group']
                if options.tenant_string_pattern in default_url_group:
                    group_name = default_url_group.replace(options.tenant_string_pattern, tenant)
            else:
                group_name = found
        try:
            group_memberships = authnz_status['claims']['groups']
        except Exception as e:
            logging.info('Could not get group memberships - choosing default memberships')
            default_membership = group_config['default_memberships']
            group_memberships = []
            for group in default_membership:
                if options.tenant_string_pattern in group:
                    new = group.replace(options.tenant_string_pattern, tenant)
                else:
                    new = group
                group_memberships.append(new)
        return group_name, group_memberships

    def enforce_group_logic(self, group_name, group_memberships, tenant, group_config):
        """
        Optionally check that:
            - provided group name matches group name regex pattern
            - tenant name contained in provided group name
            - requestor is member of provided group name

        """
        if not group_config['enabled']:
            return
        try:
            if group_config['valid_group_regex']:
                is_valid_groupname = re.compile(r'{}'.format(group_config['valid_group_regex']))
                assert is_valid_groupname.match(group_name)
        except (AssertionError, Exception) as e:
            logging.error('invalid group name: %s', group_name)
            raise e
        try:
            if group_config['ensure_tenant_in_group_name']:
                assert tenant in group_name
        except (AssertionError, Exception) as e:
            logging.error('tenant %s not in group name: %s', tenant, group_name)
            raise e
        try:
            if group_config['enforce_membership']:
                assert group_name in group_memberships
        except (AssertionError, Exception) as e:
           logging.error('user not member of group')
           raise e

    def is_reserved_resource(self, work_dir, resource):
        """
        Prevent access to API-owned resources.

        Criteria
        --------
        One of either:

        1. hidden files
            - starting with .
        2. merged resumable files
            - endswith .uuid
        3. partial upload files
            - endswith .uuid.part
        4. resumable data folders
            - uuid4, has files inside with chunk.num

        Returns
        -------
        bool

        """
        resource_dir = resource.split('/')[0]
        if resource.startswith('.'):
            logging.error('hidden files/folder not accessible')
            return False
        elif re.match(r'(.+).([a-f\d0-9-]{32,36})$', resource):
            logging.error('merged resumable files not accessible')
            return False
        elif re.match(r'(.+).([a-f\d0-9-]{32,36}).part$', resource):
            logging.error('partial upload files not accessible')
            return False
        elif _IS_VALID_UUID.match(resource_dir):
            potential_target = os.path.normpath(f'{work_dir}/{resource_dir}')
            if os.path.lexists(potential_target) and os.path.isdir(potential_target):
                content = os.listdir(potential_target)
                for entry in content:
                    if re.match(r'(.+).chunk.[0-9]+$', entry):
                        logging.error('resumable directories not accessible')
                        return False
        return True

    def handle_mq_publication(self, mq_config=None, data=None):
        """
        Publish a message to RabbitMQ, as the result of a HTTP request.
        NB: The API assumes that a vhost has been created.

        Parameters
        ----------
        mq_config: dict
            enabled: bool, required
            exchange: str, optional
            version: str, e.g. v1, optional
            routing_key: str, period separated string, e.g. k.v1.foo, optional
        data: dict, no structure required

        Implementation
        --------------
        By default, messages are published with the following routing key:

            routing key: k.{version}.{tenant}.{endpoint}

        Exchanges are topic exchanges, and queues receive messages
        based on binding keys. These binding keys can have varying
        levels of specificity, such as:

            k.#                 - all
            k.v1.#              - all for v1
            k.v1.p11.#          - all for v1, and tenant p11
            k.v1.p11.survey     - only for v1, p11 and the survey backend

        For a backend to produce messages, it's config must be set as, e.g.:

            mq:
              enabled: True
              exchange: 'ex_apps'
              version: 'v1'
              methods:
                GET: False
                HEAD: False
                PUT: True
                PATCH: True
                DELETE: True

        Defaults can be over-ridden by providing mq_config.

        """
        self.pika_client = self.application.settings.get('pika_client')
        if not self.pika_client:
            return
        if not mq_config:
            return
        if not mq_config.get('enabled'):
            return
        if not mq_config.get('methods').get(self.request.method):
            return
        try:
            default_version = 'v1'
            default_rkey = f'k.{default_version}.{self.tenant}.{self.endpoint}'
            ex =  mq_config.get('exchange')
            ver = (
                default_version if not mq_config.get('version')
                else mq_config.get('version')
            )
            rkey = (
                default_rkey if not mq_config.get('routing_key')
                else mq_config.get('routing_key')
            )
            uri = (
                self.request.headers.get('Original-Uri') if self.request.headers.get('Original-Uri')
                else self.request.uri
            )
            self.pika_client.publish_message(
                exchange=ex,
                routing_key=rkey,
                method=self.request.method,
                uri=uri,
                version=ver,
                data=data
            )
        except Exception as e:
            summary = f'exchange: {exchange}, routing_key: {rkey}, version: {ver}'
            msg = f'problem publishing message, {summary}'
            logging.error(msg)
            logging.error(e)
        return


class GenericFormDataHandler(AuthRequestHandler):

    def initialize(self, backend):
        try:
            self.backend = backend
            self.endpoint = self.request.uri.split('/')[3]
            self.tenant = tenant_from_url(self.request.uri)
            assert options.valid_tenant.match(self.tenant)
            self.tenant_dir_pattern = options.config['backends']['disk'][backend]['import_path']
            self.tsd_hidden_folder = None
            if backend == 'sns': # hope to deprecate this with new nettskjema integration
                self.tsd_hidden_folder_pattern = options.config['backends']['disk'][backend]['subfolder_path']
            self.request_hook = options.config['backends']['disk'][backend]['request_hook']
            self.check_tenant = options.config['backends']['disk'][backend].get('check_tenant')
            try:
                disabled_group_config = {
                    'enabled': False,
                    'default_url_group': '',
                    'default_memberships': [],
                    'ensure_tenant_in_group_name': False,
                    'valid_group_regex': None,
                    'enforce_membership': False
                }
                self.group_config = options.config['backends']['disk'][backend]['group_logic']
                if not self.group_config['enabled']:
                    self.group_config = disabled_group_config
            except Exception as e:
                self.group_config = disabled_group_config
        except (Exception, AssertionError) as e:
            logging.error('could not initalize form data handler')

    def prepare(self):
        try:
            self.err = 'request failed'
            if options.maintenance_mode_enabled:
                self.set_status(503)
                self.err = 'Service temporarily unavailable'
                raise Exception
            self.new_paths = []
            self.group_name = None
            self.authnz = self.process_token_and_extract_claims(
                check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
            )
            if not self.authnz:
                self.err = 'Unauthorized'
                self.set_status(401)
                raise Exception
            if not self.request.files['file']:
                self.err = 'No file(s) supplied with upload request'
                logging.error(self.err)
                self.set_status(400)
                raise Exception
            # check group logic here
            try:
                authnz_status = self.authnz
                group_name, group_memberships = self.get_group_info(
                    self.tenant, self.group_config, authnz_status
                )
                self.enforce_group_logic(
                    group_name, group_memberships, self.tenant, self.group_config
                )
            except Exception as e:
                self.err = 'group checks failed'
                logging.error(e)
                logging.error(self.err)
                raise e
        except Exception as e:
            if self._status_code not in [401, 503]:
                self.set_status(400)
            self.finish()

    def write_files(self, filemode, tenant):
        try:
            for i in range(len(self.request.files['file'])):
                filename = check_filename(self.request.files['file'][i]['filename'],
                                          disallowed_start_chars=options.start_chars)
                filebody = self.request.files['file'][i]['body']
                if len(filebody) == 0:
                    logging.error('Trying to upload an empty file: %s - not allowed, since nonsensical', filename)
                    raise Exception('EmptyFileBodyError')
                # add all optional parameters to file writer
                # this is used for nettskjema specific backend
                written = self.write_file(filemode, filename, filebody, tenant)
                assert written
            return True
        except Exception as e:
            logging.error(e)
            logging.error('Could not process files')
            return False


    def write_file(self, filemode, filename, filebody, tenant):
        try:
            if self.backend == 'sns':
                tsd_hidden_folder = sns_dir(self.tsd_hidden_folder_pattern, tenant, self.request.uri, options.tenant_string_pattern)
                tenant_dir = sns_dir(self.tenant_dir_pattern, tenant, self.request.uri, options.tenant_string_pattern)
            else:
                tenant_dir = self.tenant_dir_pattern.replace(options.tenant_string_pattern, tenant)
            self.path = os.path.normpath(tenant_dir + '/' + filename)
            # add the partial file indicator, check existence
            self.path_part = self.path + '.' + str(uuid4()) + '.part'
            if os.path.lexists(self.path_part):
                logging.error('trying to write to partial file - killing request')
                raise Exception
            if os.path.lexists(self.path):
                logging.info('%s already exists, renaming to %s', self.path, self.path_part)
                os.rename(self.path, self.path_part)
                assert os.path.lexists(self.path_part)
                assert not os.path.lexists(self.path)
            self.path, self.path_part = self.path_part, self.path
            with open(self.path, filemode) as f:
                f.write(filebody)
                os.rename(self.path, self.path_part)
                os.chmod(self.path_part, _RW_RW___)
            self.new_paths.append(self.path_part)
            if self.backend == 'sns':
                subfolder_path = os.path.normpath(tsd_hidden_folder + '/' + filename)
                try:
                    shutil.copy(self.path_part, subfolder_path)
                    os.chmod(subfolder_path, _RW_RW___)
                    self.new_paths.append(subfolder_path)
                except Exception as e:
                    logging.error(e)
                    logging.error('Could not copy file %s to .tsd folder', self.path_part)
                    return False
            return True
        except (Exception, AssertionError) as e:
            logging.error(e)
            logging.error('Could not write to file')
            return False

    def on_finish(self):
        if self.request.method in ('PUT','POST', 'PATCH'):
            try:
                if self.request_hook['enabled']:
                    for path in self.new_paths:
                        call_request_hook(self.request_hook['path'],
                                          [path, self.requestor, options.api_user, self.group_name],
                                          as_sudo=self.request_hook['sudo'])
            except Exception as e:
                logging.error(e)



class FormDataHandler(GenericFormDataHandler):

    def handle_data(self, filemode, tenant):
        try:
            assert self.write_files(filemode, tenant)
            self.set_status(201)
            self.write({'message': 'data uploaded'})
        except Exception:
            self.set_status(400)
            self.write({'message': 'could not upload data'})

    def post(self, tenant):
        self.handle_data('ab+', tenant)

    def patch(self, tenant):
        self.handle_data('ab+', tenant)

    def put(self, tenant):
        self.handle_data('wb+', tenant)

    def head(self, tenant):
        self.set_status(201)


class SnsFormDataHandler(GenericFormDataHandler):

    def handle_data(self, filemode, tenant):
        try:
            assert self.write_files(filemode, tenant)
            self.set_status(201)
            self.write({'message': 'data uploaded'})
        except Exception:
            self.set_status(400)
            self.write({'message': 'could not upload data'})

    def post(self, tenant, keyid, formid):
        self.handle_data('ab+', tenant)

    def patch(self, tenant, keyid, formid):
        self.handle_data('ab+', tenant)

    def put(self, tenant, keyid, formid):
        self.handle_data('wb+', tenant)

    def head(self, tenant, keyid, formid):
        self.set_status(201)


class ResumablesHandler(AuthRequestHandler):

    """
    Manage resumables, report information.

    Implementation
    --------------
    To continue a resumable upload which has stopped, clients
    can get information about data stored by the server.

    This class provides a GET method, which returns the relevant
    information to the client, for a given upload_id, and/or file.

    This information is:

    - filename
    - sequence number of last chunk
    - chunk size
    - upload id
    - md5sum of the last chunk
    - previos offset in bytes
    - next offset in bytes (total size of merged file)
    - resumable key (server-side directory specified in url)

    There are two possible scenarios: 1) the client knows the upload_id
    associated with the file which needs to be resumed, or 2) the client
    only knows the name of the file which needs to be resumed.

    Scenario 1
    ----------
    In scenario #1, the upload_id is provided, and the server returns
    the information.

    Scenario 2
    ----------
    In scenario #2, the server will look at all potential resumables,
    and try to find a match based on the filename. All relevant matches
    to which the authenticated user has access are returned, including
    information about how much data has been uploaded. The client can
    then choose to resume the one with the most data, and delete the
    remaining ones.

    """

    def initialize(self, backend):
        try:
            self.backend = backend
            self.endpoint = self.request.uri.split('/')[3]
            self.tenant = tenant_from_url(self.request.uri)
            assert options.valid_tenant.match(self.tenant)
            self.import_dir = options.config['backends']['disk'][backend]['import_path']
            assert create_cluster_dir_if_not_exists(self.import_dir, self.tenant, options.tenant_string_pattern)
            self.tenant_dir = self.import_dir.replace(options.tenant_string_pattern, self.tenant)
            self.check_tenant = options.config['backends']['disk'][backend].get('check_tenant')
        except (AssertionError, Exception) as e:
            logging.error('Could not initialize resumables handler')
            logging.error(e)
            raise e


    def prepare(self):
        try:
            self.err = 'Unauthorized'
            if options.maintenance_mode_enabled:
                self.set_status(503)
                self.err = 'Service temporarily unavailable'
                raise Exception(self.err)
            self.authnz = self.process_token_and_extract_claims(
                check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
            )
        except Exception as e:
            self.finish()


    def get(self, tenant, filename=None):
        self.message = {'filename': filename, 'id': None, 'chunk_size': None, 'max_chunk': None}
        upload_id = None
        try:
            try:
                if filename:
                    secured_filename = check_filename(url_unescape(filename),
                                                      disallowed_start_chars=options.start_chars)
            except Exception:
                logging.error('not able to check for resumable due to bad input')
                raise Exception
            try:
                upload_id = url_unescape(self.get_query_argument('id'))
            except Exception:
                upload_id = None
            res = SerialResumable(self.tenant_dir, self.requestor)
            if not filename:
                info = res.list_all(self.tenant_dir, self.requestor)
            else:
                info = res.info(self.tenant_dir, secured_filename, upload_id, self.requestor)
            self.set_status(200)
            self.write(info)
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write(self.message)


    def delete(self, tenant, filename):
        self.message = {'message': 'cannot delete resumable'}
        try:
            try:
                secured_filename = check_filename(url_unescape(filename),
                                                  disallowed_start_chars=options.start_chars)
            except Exception:
                logging.error('not able to check for resumable due to bad input')
                raise Exception
            try:
                upload_id = url_unescape(self.get_query_argument('id'))
            except Exception:
                raise Exception('upload id required to delete resumable')
            res = SerialResumable(self.tenant_dir, self.requestor)
            assert res.delete(self.tenant_dir, filename, upload_id, self.requestor)
            self.set_status(200)
            self.write({'message': 'resumable deleted'})
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write(self.message)


@stream_request_body
class StreamHandler(AuthRequestHandler):

    #pylint: disable=line-too-long

    """
    This class writes request data to files for PUT, POST and PATCH methods,
    optionally calling request hooks after writing has finished.

    The following steps are performed:

    call initialize:
    1. load backend config, depending on the url

    call prepare
    2. extract claims from the access token
    3. validate url
    4. load url parameters
    5. process content-type header
    6. if PATCH, prepare the resumable
    7. rename the target file to .part (indicating an active upload)
    8. optionally dispatch to a custom content-type request handler
    9. open the file, set file permissions

    call data_received
    10. write data to target


    call put, post, patch
    11. close the file
    12. if PATCH, either merge the new chunk or finalise the resumable

    call on_finish, or on_connection_close
    13. rename the file
    14. optionally call a request hook (setting permissions and moving the file)

    Resumable uploads therefore have the following request life cycle:
    1. prepare
        - setup
        - checks
    2. process
        - open
        - write
        - close
    3. complete
        - merge chunk
        - finalise

    """

    def decrypt_aes_key(self, b64encoded_pgpencrypted_key):
        gpg = _import_keys(options.config)
        key = base64.b64decode(b64encoded_pgpencrypted_key)
        decr_aes_key = str(gpg.decrypt(key)).strip()
        return decr_aes_key


    def start_openssl_proc(self, output_file=None, base64=True):
        cmd = ['openssl', 'enc', '-aes-256-cbc', '-d'] + self.aes_decryption_args_from_headers()
        if output_file is not None:
            cmd = cmd + ['-out', output_file]
        if base64:
            cmd = cmd + ['-a']
        return subprocess.Popen(cmd,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE if output_file is None else None)


    def aes_decryption_args_from_headers(self):
        try:
            decr_aes_key = self.decrypt_aes_key(self.request.headers['Aes-Key'])
        except Exception as e:
            logging.error(e)
        if "Aes-Iv" in self.request.headers:
            return ['-iv', self.request.headers["Aes-Iv"], '-K', decr_aes_key]
        else:
            return ['-pass', 'pass:%s' % decr_aes_key]


    def handle_aes(self, content_type):
        self.custom_content_type = content_type
        self.proc = self.start_openssl_proc(output_file=self.path)


    def handle_aes_octet_stream(self, content_type):
        self.custom_content_type = 'application/aes'
        self.proc = self.start_openssl_proc(output_file=self.path, base64=False)


    def handle_tar(self, content_type, tenant_dir):
        if 'gz' in content_type:
            tarflags = '-xzf'
        else:
            tarflags = '-xf'
        self.custom_content_type = content_type
        self.proc = subprocess.Popen(['tar', '-C', tenant_dir, tarflags, '-'],
                                      stdin=subprocess.PIPE)


    def handle_tar_aes(self, content_type, tenant_dir):
        if 'gz' in content_type:
            tarflags = '-xzf'
        else:
            tarflags = '-xf'
        self.custom_content_type = content_type
        self.openssl_proc = self.start_openssl_proc()
        self.tar_proc = subprocess.Popen(['tar', '-C', tenant_dir, tarflags, '-'],
                                 stdin=self.openssl_proc.stdout)


    def handle_gz(self, content_type, filemode):
        self.custom_content_type = content_type
        self.target_file = open(self.path, filemode)
        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                             stdin=subprocess.PIPE,
                                             stdout=self.target_file)


    def handle_gz_aes(self, content_type, filemode):
        self.custom_content_type = content_type
        self.target_file = open(self.path, filemode)
        self.openssl_proc = self.start_openssl_proc()
        self.gunzip_proc = subprocess.Popen(['gunzip', '-c', '-'],
                                             stdin=self.openssl_proc.stdout,
                                             stdout=self.target_file)

    def handle_nacl_stream(self, headers):
        self.custom_content_type = headers['Content-Type']
        self.nacl_stream_buffer = b''
        try:
            self.nacl_nonce = options.sealed_box.decrypt(
                base64.b64decode(headers['Nacl-Nonce'])
            )
            self.nacl_key = options.sealed_box.decrypt(
                base64.b64decode(headers['Nacl-Key'])
            )
        except Exception as e:
            logging.error(e)
            logging.error('Could not decrypt Nacl headers')
            raise Exception
        try:
            self.nacl_chunksize = int(headers['Nacl-Chunksize'])
        except KeyError:
            logging.error('Missing Nacl-Chunksize header - cannot decrypt data')
            raise Exception


    def initialize(self, backend):
        try:
            self.backend = backend
            self.endpoint = self.request.uri.split('/')[3]
            self.tenant = tenant_from_url(self.request.uri)
            assert options.valid_tenant.match(self.tenant)
            self.import_dir = options.config['backends']['disk'][backend]['import_path']
            assert create_cluster_dir_if_not_exists(self.import_dir, self.tenant, options.tenant_string_pattern)
            self.tenant_dir = self.import_dir.replace(options.tenant_string_pattern, self.tenant)
            self.backend = backend
            self.request_hook = options.config['backends']['disk'][backend]['request_hook']
            self.group_config = options.config['backends']['disk'][backend]['group_logic']
            self.check_tenant = options.config['backends']['disk'][backend].get('check_tenant')
            self.mq_config = options.config['backends']['disk'][backend].get('mq')
        except AssertionError as e:
            self.backend = backend
            logging.error('URI does not contain a valid tenant')
            raise e


    @gen.coroutine
    def prepare(self):
        """
        This sets up state for the part of the request handler which writes data to disk.

        - authorization
        - input validation
        - file write mode
        - content-type processing
        - filename construction
        - calling request-specific handlers
        - ending requests which do not meet criteria

        """
        try:
            self.completed_resumable_file = False
            self.target_file = None
            self.custom_content_type = None
            self.path = None
            self.path_part = None
            self.chunk_order_correct = True
            self.chunk_num = None
            self.on_finish_called = False
            filemodes = {'PUT': 'wb+', 'PATCH': 'wb+'}
            try:
                self.authnz = self.process_token_and_extract_claims(
                    check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
                )
            except Exception as e:
                logging.error(e)
                raise Exception
            try:
                # 1. Check tenant reference
                try:
                    tenant = tenant_from_url(self.request.uri)
                    self.tenant = tenant
                    assert options.valid_tenant.match(tenant)
                except AssertionError as e:
                    logging.error('URI does not contain a valid tenant')
                    raise e
                # 2. get group param
                try:
                    self.group_name = url_unescape(self.get_query_argument('group'))
                except Exception:
                    self.group_name = tenant + '-member-group'
                filemode = filemodes[self.request.method]
                # 3. start processing the data
                try:
                    # 3.1 extract info from uri
                    content_type = self.request.headers['Content-Type']
                    uri_filename = self.request.uri.split('?')[0].split('/')[-1]
                    filename = check_filename(url_unescape(uri_filename),
                                              disallowed_start_chars=options.start_chars)
                    # 3.2 optionally create dirs
                    # 3.2.1 tenant dir
                    if options.create_tenant_dir:
                        if not os.path.lexists(self.tenant_dir):
                            os.makedirs(self.tenant_dir)
                    # 3.2.2 destination dir
                    self.resource_dir = None
                    try:
                        resource_references = self.request.uri.split('?')[0].split('/')[5:]
                        url_dirs = url_unescape('/'.join(resource_references[:-1]))
                        self.resource_dir = os.path.normpath(f'{self.tenant_dir}/{url_dirs}')
                        if not os.path.lexists(self.resource_dir):
                            logging.info(f'creating resource dir: {self.resource_dir}')
                            os.makedirs(self.resource_dir)
                            target = self.tenant_dir
                            for _dir in url_dirs.split('/'):
                                target += f'/{_dir}'
                                try:
                                    if self.group_config['enabled']:
                                        subprocess.call(['chmod', '2770', target])
                                        subprocess.call(['sudo', 'chown', f'{options.api_user}:{self.group_name}', target])
                                except (Exception, OSError):
                                    logging.error('could not set permissions on upload directories')
                                    raise Exception
                    except Exception as e:
                        logging.error(e)
                        raise Exception
                    # 3.3 handle resumable, if relavant
                    if self.request.method == 'PATCH':
                        # select resumable key:
                        # then we remove the group name from url_dirs
                        # because this is handled transparently
                        # (for better or for worse)
                        if self.group_config['enabled']:
                            self.res_key = url_dirs.replace(self.group_name, '')
                            # potentially replace '' with None
                            self.res_key = None if not self.res_key else self.res_key
                        else:
                            self.res_key = url_dirs
                        self.res = SerialResumable(self.tenant_dir, self.requestor)
                        url_chunk_num = url_unescape(self.get_query_argument('chunk'))
                        url_upload_id = url_unescape(self.get_query_argument('id'))
                        self.chunk_num, \
                        self.upload_id, \
                        self.completed_resumable_file, \
                        self.chunk_order_correct, \
                        filename = self.res.prepare(
                                self.tenant_dir,
                                filename,
                                url_chunk_num,
                                url_upload_id,
                                self.group_name,
                                self.requestor,
                                self.res_key
                            )
                        if not self.chunk_order_correct:
                            logging.error('incorrect chunk order')
                            raise Exception
                    # 3.4 ensure we do not write to active file
                    self.path = os.path.normpath(self.tenant_dir + '/' + filename)
                    self.path_part = self.path + '.' + str(uuid4()) + '.part'
                    if os.path.lexists(self.path_part):
                        logging.error('trying to write to partial file - killing request')
                        raise Exception
                    # 3.5 ensure idempotency
                    if os.path.lexists(self.path):
                        if os.path.isdir(self.path):
                            logging.info('directory: %s already exists due to prior upload, removing', self.path)
                            shutil.rmtree(self.path)
                        else:
                            logging.info('%s already exists, renaming to %s', self.path, self.path_part)
                            os.rename(self.path, self.path_part)
                            assert os.path.lexists(self.path_part)
                            assert not os.path.lexists(self.path)
                    # 3.6 rename
                    self.path, self.path_part = self.path_part, self.path
                    # 3.7 invoke custom content type handlers, if relevant
                    if content_type == 'application/aes':
                        self.handle_aes(content_type)
                    elif content_type == 'application/aes-octet-stream':
                        self.handle_aes_octet_stream(content_type)
                    elif content_type in ['application/tar', 'application/tar.gz']:
                        self.handle_tar(content_type, self.tenant_dir)
                    elif content_type in ['application/tar.aes', 'application/tar.gz.aes']:
                        self.handle_tar_aes(content_type, self.tenant_dir)
                    elif content_type == 'application/gz':
                        self.handle_gz(content_type, filemode)
                    elif content_type == 'application/gz.aes':
                        self.handle_gz_aes(content_type, filemode)
                    elif content_type == 'application/octet-stream+nacl':
                        self.handle_nacl_stream(self.request.headers)
                        self.target_file = open(self.path, filemode)
                        os.chmod(self.path, _RW______)
                    else: # 3.8 no custom content type
                        if self.request.method != 'PATCH':
                            self.custom_content_type = None
                            self.target_file = open(self.path, filemode)
                            os.chmod(self.path, _RW______)
                        elif self.request.method == 'PATCH':
                            self.custom_content_type = None
                            if not self.completed_resumable_file:
                                self.target_file = self.res.open_file(self.path, filemode)
                except KeyError:
                    raise Exception('No content-type - do not know what to do with data')
            # 3.9 handle any errors
            except Exception as e:
                try:
                    if self.target_file:
                        self.target_file.close()
                    os.rename(self.path, self.path_part)
                except AttributeError as e:
                    logging.error(e)
                    logging.error('No file to close after all - so nothing to worry about')
                    raise e
        except Exception as e:
            logging.error('stream handler failed')
            info = 'stream processing failed'
            if self.chunk_order_correct is False:
                self.set_status(200)
                info = 'chunk_order_incorrect'
            self.finish({'message': info})


    @gen.coroutine
    def data_received(self, chunk):
        try:
            if not self.custom_content_type:
                if self.request.method == 'PATCH':
                    self.res.add_chunk(self.target_file, chunk)
                else:
                    self.target_file.write(chunk)
            elif self.custom_content_type == 'application/octet-stream+nacl':
                for byte in chunk:
                    self.nacl_stream_buffer += bytes([byte])
                    if len(self.nacl_stream_buffer) % self.nacl_chunksize == 0:
                        decrypted = libnacl.crypto_stream_xor(
                            self.nacl_stream_buffer,
                            self.nacl_nonce,
                            self.nacl_key
                        )
                        self.target_file.write(decrypted)
                        self.nacl_stream_buffer = b''
            elif self.custom_content_type in ['application/tar', 'application/tar.gz',
                                              'application/aes']:
                self.proc.stdin.write(chunk)
                if not chunk:
                    self.proc.stdin.flush()
            elif self.custom_content_type in ['application/tar.aes', 'application/tar.gz.aes']:
                self.openssl_proc.stdin.write(chunk)
                if not chunk:
                    self.openssl_proc.stdin.flush()
                    self.tar_proc.stdin.flush()
            elif self.custom_content_type == 'application/gz':
                self.gunzip_proc.stdin.write(chunk)
                if not chunk:
                    self.gunzip_proc.stdin.flush()
            elif self.custom_content_type == 'application/gz.aes':
                self.openssl_proc.stdin.write(chunk)
                if not chunk:
                    self.openssl_proc.stdin.flush()
                    self.gunzip_proc.stdin.flush()
        except Exception as e:
            logging.error(e)
            logging.error("something went wrong with stream processing have to close file")
            if self.target_file:
                self.target_file.close()
            os.rename(self.path, self.path_part)
            self.send_error("something went wrong")

    def put(self, tenant, uri_filename=None):
        if not self.custom_content_type:
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type == 'application/octet-stream+nacl':
            if self.nacl_stream_buffer:
                decrypted = libnacl.crypto_stream_xor(
                            self.nacl_stream_buffer,
                            self.nacl_nonce,
                            self.nacl_key
                        )
                self.nacl_stream_buffer = b''
                self.target_file.write(decrypted)
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar', 'application/tar.gz',
                                          'application/aes']:
            out, err = self.proc.communicate()
            if self.custom_content_type == 'application/aes':
                os.rename(self.path, self.path_part)
        elif self.custom_content_type in ['application/tar.aes', 'application/tar.gz.aes']:
            out, err = self.openssl_proc.communicate()
            out, err = self.tar_proc.communicate()
        elif self.custom_content_type == 'application/gz':
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        elif self.custom_content_type == 'application/gz.aes':
            out, err = self.openssl_proc.communicate()
            out, err = self.gunzip_proc.communicate()
            self.target_file.close()
            os.rename(self.path, self.path_part)
        self.set_status(201)
        self.write({'message': 'data streamed'})


    def patch(self, tenant, uri_filename=None):
        if not self.completed_resumable_file:
            self.res.close_file(self.target_file)
            # if the path to which we want to rename the file exists
            # then we have been writing the same chunk concurrently
            # from two different processes, so we should not do it
            if not os.path.lexists(self.path_part):
                os.rename(self.path, self.path_part)
                filename = os.path.basename(self.path_part).split('.chunk')[0]
                self.res.merge_chunk(
                    self.tenant_dir,
                    os.path.basename(self.path_part),
                    self.upload_id,
                    self.requestor
                )
            else:
                self.write({'message': 'chunk_order_incorrect'})
        else:
            self.completed_resumable_filename = self.res.finalise(
                self.tenant_dir,
                os.path.basename(self.path_part),
                self.upload_id,
                self.requestor
            )
            filename = os.path.basename(self.completed_resumable_filename)
        self.set_status(201)
        self.write({
            'filename': filename,
            'id': self.upload_id,
            'max_chunk': self.chunk_num,
            'key': self.res_key
            }
        )


    def head(self, tenant, uri_filename=None):
        self.set_status(201)


    def on_finish(self):
        """
        Called after each request before closing the connection.

        1. Clean up any open files, if an error occurred
        2. Call the request hook, if configured
        3. Publish message to rabbitmq, if configured

        """
        try:
            if not self.target_file.closed:
                self.target_file.close()
                os.rename(self.path, self.path_part)
        except AttributeError as e:
            pass
        resource_created = (
            self.request.method == 'PUT' or (
                self.request.method == 'PATCH' and
                self.chunk_num == 'end'
            )
        )
        if resource_created:
            try:
                # switch path variables back
                if not self.completed_resumable_file:
                    path, path_part = self.path_part, self.path
                else:
                    path = self.completed_resumable_filename
                resource_path = move_data_to_folder(path, self.resource_dir)
            except Exception as e:
                logging.info('could not move data to destination folder')
                logging.info(e)
            try:
                if self.request_hook['enabled']:
                    call_request_hook(
                        self.request_hook['path'],
                        [resource_path, self.requestor, options.api_user, self.group_name],
                        as_sudo=self.request_hook['sudo']
                    )
            except Exception as e:
                logging.info('problem calling request hook')
                logging.info(e)
            try:
                message_data = {
                    'path': resource_path,
                    'requestor': self.requestor,
                    'group': self.group_name
                }
                self.handle_mq_publication(
                    mq_config=self.mq_config,
                    data=message_data
                )
            except Exception as e:
                logging.error(e)
            self.on_finish_called = True


    def on_connection_close(self):
        """
        Called when clients close the connection.

        1. Close open file, move it to destination
        2. Publish message to rabbitmq, if configured

        """
        try:
            if not self.target_file.closed:
                self.target_file.close()
                path = self.path
                resource_path = move_data_to_folder(path, self.resource_dir)
                if self.request_hook['enabled']:
                    call_request_hook(
                        self.request_hook['path'],
                        [resource_path, self.requestor, options.api_user, self.group_name],
                        as_sudo=self.request_hook['sudo']
                    )
                if not self.on_finish_called:
                    message_data = {
                        'path': resource_path,
                        'requestor': self.requestor,
                        'group': self.group_name
                    }
                    self.handle_mq_publication(
                        mq_config=self.mq_config,
                        data=message_data
                    )
        except (AttributeError, Exception) as e:
            logging.error(e)


@stream_request_body
class ProxyHandler(AuthRequestHandler):

    def initialize(self, backend, namespace, endpoint):
        self.backend = backend
        self.namespace = namespace
        self.endpoint = endpoint
        self.allow_export = options.config['backends']['disk'][backend]['allow_export']
        self.allow_list = options.config['backends']['disk'][backend]['allow_list']
        self.allow_info = options.config['backends']['disk'][backend]['allow_info']
        self.allow_delete = options.config['backends']['disk'][backend]['allow_delete']
        self.export_max = options.config['backends']['disk'][backend]['export_max_num_list']
        self.has_posix_ownership = options.config['backends']['disk'][backend]['has_posix_ownership']
        self.check_tenant = options.config['backends']['disk'][backend].get('check_tenant')
        self.mq_config = options.config['backends']['disk'][backend].get('mq')
        try:
            missing_group_config = {
                'enabled': False,
                'default_url_group': '',
                'default_memberships': [],
                'ensure_tenant_in_group_name': False,
                'valid_group_regex': None,
                'enforce_membership': False
            }
            try:
                self.group_config = options.config['backends']['disk'][backend]['group_logic']
            except KeyError:
                self.group_config = missing_group_config
            self.CHUNK_SIZE = options.export_chunk_size
            tenant = tenant_from_url(self.request.uri)
            assert options.valid_tenant.match(tenant)
            self.backend_paths = options.config['backends']['disk'][backend]
            self.export_path_pattern = self.backend_paths['export_path']
            self.export_dir = self.export_path_pattern.replace(options.tenant_string_pattern, tenant)
            self.export_policy = options.config['backends']['disk'][backend]['export_policy']
            self.import_dir = options.config['backends']['disk'][backend]['import_path']
            self.import_dir = self.import_dir.replace(options.tenant_string_pattern, tenant)
        except Exception as e:
            self.group_config = disabled_group_config


    @gen.coroutine
    def prepare(self):
        """Initiate internal async HTTP request to handle body.
        """
        self.error = None
        try:
            # 0. If in maintenance mode, stop
            if options.maintenance_mode_enabled:
                self.set_status(503)
                self.error = 'Service temporarily unavailable'
                raise Exception(self.error)
            # 1. Set up internal variables, check method supported
            try:
                self.chunks = tornado.queues.Queue(1)
                if self.request.method in ['HEAD', 'GET', 'DELETE']:
                    body = None
                elif self.request.method == 'POST':
                    self.set_status(405)
                    self.error = 'POST not supported'
                    logging.error(self.error)
                    raise Exception
                else:
                    body = self.body_producer
            except Exception as e:
                logging.error('Could not set up internal async variables')
                raise e
            # 2. Authentication and authorization
            try:
                self.authnz = self.process_token_and_extract_claims(
                    check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
                )
            except Exception as e:
                self.error = 'Access token invalid'
                logging.error(self.error)
                raise e
            # 3. Validate tenant identifier in URI
            try:
                tenant = tenant_from_url(self.request.uri)
                assert options.valid_tenant.match(tenant)
                self.tenant = tenant
            except AssertionError as e:
                self.error = 'URI does not contain a valid tenant'
                logging.error(self.error)
                raise e
            # 4. Set the filename
            try:
                uri = self.request.uri.split('?')[0]
                uri_parts = self.request.uri.split('?')[0].split('/')
                if len(uri_parts) >= 6:
                    basename = uri_parts[-1]
                    filename = basename.split('?')[0]
                    self.filename = check_filename(url_unescape(filename),
                                                   disallowed_start_chars=options.start_chars)
                else:
                    if self.request.method in ('PUT', 'PATCH'):
                        logging.warning('legacy Filename header used')
                        try:
                            self.filename = check_filename(self.request.headers['Filename'],
                                                           disallowed_start_chars=options.start_chars)
                        except KeyError:
                            self.filename = datetime.datetime.now().isoformat() + '.txt'
                        uri_parts.append(self.filename)
                        # inject the filename into the uri
                        if '?' in uri:
                            uri = uri.replace('?', f'{self.filename}?')
                        else:
                            uri = f'{uri}/{self.filename}'
                    else:
                        self.filename = None # do not need it here
            except Exception as e:
                self.error = 'could not process URI'
                logging.error(e)
                logging.error(self.error)
                raise Exception
            # 5. ensure resource is not reserved
            try:
                delimiter = self.endpoint if self.endpoint else self.namespace
                resource = uri.split(f'/{delimiter}/')[-1]
                if self.request.method in ('GET', 'HEAD', 'DELETE'):
                    work_dir = self.export_dir
                elif self.request.method in ('PUT', 'PATCH'):
                    work_dir = self.import_dir
                if resource == uri:
                    pass # cannot be reserved, no need to check
                else:
                    assert self.is_reserved_resource(work_dir, url_unescape(resource))
            except (AssertionError, Exception) as e:
                self.error = 'reserved resource name'
                logging.error(self.error)
                self.set_status(400)
                raise Exception
            # 6. Validate groups
            try:
                group_name, group_memberships = self.get_group_info(tenant, self.group_config, self.authnz)
                self.enforce_group_logic(group_name, group_memberships, tenant, self.group_config)
            except Exception as e:
                self.error = 'could not perform group checks'
                logging.error(e)
                logging.error(self.error)
                raise e
            # 7. Set headers for internal request
            try:
                headers = {'Authorization': 'Bearer ' + self.jwt, 'Original-Uri': self.request.uri}
                header_keys = self.request.headers.keys()
                if 'Content-Type' not in header_keys:
                    content_type = 'application/octet-stream'
                elif 'Content-Type' in header_keys:
                    content_type = self.request.headers['Content-Type']
                    if content_type == 'application/octet-stream+nacl':
                        required_nacl_headers = ['Nacl-Key', 'Nacl-Nonce', 'Nacl-Chunksize']
                        for required_nacl_header in required_nacl_headers:
                            if required_nacl_header not in header_keys:
                                logging.error(f'missing {required_nacl_header}')
                                raise Exception
                            headers[required_nacl_header] = self.request.headers[required_nacl_header]
                        if int(headers['Nacl-Chunksize']) > options.max_nacl_chunksize:
                            self.error = f'Nacl-Chunksize larger than max allowed: {options.max_nacl_chunksize}'
                            logging.error(self.error)
                            raise Exception
                if 'Aes-Key' in header_keys:
                    headers['Aes-Key'] = self.request.headers['Aes-Key']
                if 'Aes-Iv' in header_keys:
                    headers['Aes-Iv'] = self.request.headers['Aes-Iv']
                headers['Content-Type'] = content_type
            except Exception as e:
                self.error = 'Could not prepare headers for async request handling'
                logging.error(e)
                logging.error(self.error)
                raise e
            # 8. Build URL
            # 8.1 collect params
            try:
                upload_id, chunk_num = None, None
                chunk_num = url_unescape(self.get_query_argument('chunk'))
                upload_id = url_unescape(self.get_query_argument('id'))
            except Exception:
                pass
            # 8.2 enfore group logic, if enabled
            if self.group_config['enabled'] and self.request.method in ['PUT', 'PATCH']:
                # 8.2.1 if a directory is present, and not the same as the group
                if url_unescape(uri_parts[5]) != self.filename and uri_parts[5] != group_name:
                    logging.error('inconsistent group permissions')
                    raise Exception
                # 8.2.2 if group folder not in url, inject it from group_name
                if url_unescape(uri_parts[5]) == self.filename:
                    # inject appropriate value - until clients have transitioned
                    file = url_escape(self.filename)
                    resource = f'{group_name}/{file}'
            elif self.group_config['enabled'] and self.request.method in ['GET', 'HEAD']:
                # then we are operating in the TSD import directory
                if not self.filename and len(uri_parts) == 5: # no folder given
                    resource = work_dir # root dir
            # 8.3 build internal url
            self.resource = resource
            params = '?group=%s&chunk=%s&id=%s' % (group_name, chunk_num, upload_id)
            internal_url = f'http://localhost:{options.port}/v1/{tenant}/{self.namespace}/upload_stream/{resource}{params}'
            # 9. Do async request to handle incoming data
            try:
                if self.request.method in ('PUT', 'PATCH'):
                    # otherwise we are serving something
                    # so no need to pass data on
                    self.fetch_future = AsyncHTTPClient().fetch(
                        internal_url,
                        method=self.request.method,
                        body_producer=body,
                        request_timeout=12000.0, # 3 hours max
                        headers=headers)
            except Exception as e:
                logging.error('Problem in async client')
                logging.error(e)
                raise e
        except Exception as e:
            if self._status_code != 503:
                self.set_status(401)
                logging.error(self.error)
                logging.error(e)
            self.finish()

    @gen.coroutine
    def body_producer(self, write):
        while True:
            chunk = yield self.chunks.get()
            if chunk is None:
                return
            yield write(chunk)

    @gen.coroutine
    def data_received(self, chunk):
        yield self.chunks.put(chunk)

    @gen.coroutine
    def put(self, tenant, filename=None):
        """Called after entire body has been read."""
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        self.set_status(response.code)
        self.write(response.body)

    @gen.coroutine
    def patch(self, tenant, filename=None):
        """Called after entire body has been read."""
        yield self.chunks.put(None)
        # wait for request to finish.
        response = yield self.fetch_future
        code = response.code
        body = response.body
        try:
            resp = json.loads(response.body)
            if resp['message'] == 'chunk_order_incorrect':
                code = 400
                body = resp
        except Exception:
            pass
        self.set_status(code)
        self.write(body)


    def enforce_export_policy(self, policy_config, filename, tenant, size, mime_type):
        """
        Check file to ensure it meets the requirements of the export policy

        Checks
        ------
        1. For all tenants, check that the file name follows conventions
        2. For the given tenant, if a policy is specified and enabled check:
            - file size does not exceed max allowed for export
            - MIME types conform to allowed types, if policy enabled

        Returns
        -------
        (bool, <str,None>, <int,None>),
        (is_conformant, mime-type, size)

        """
        status = False # until proven otherwise
        try:
            file = os.path.basename(filename)
            check_filename(file, disallowed_start_chars=options.start_chars)
        except Exception as e:
            self.message = 'Illegal export filename: %s' % file
            logging.error(self.message)
            return status
        if tenant in policy_config.keys():
            policy = policy_config[tenant]
        else:
            policy = policy_config['default']
        if not policy['enabled']:
            status = True
            return status
        if '*' in policy['allowed_mime_types']:
            status = True
        else:
            status = True if mime_type in policy['allowed_mime_types'] else False
            if not status:
                self.message = 'not allowed to export file with MIME type: %s' % mime_type
                logging.error(self.message)
        if policy['max_size'] and size > policy['max_size']:
            logging.error('%s tried to export a file exceeding the maximum size limit', self.requestor)
            self.message = 'File size exceeds maximum allowed for %s' % tenant
            status = False
        return status


    def get_file_metadata(self, filename):
        filename_raw_utf8 = filename.encode('utf-8')
        if self.has_posix_ownership:
            # to be able to stat top level files
            # where api user is owner of top level dir
            subprocess.call(['sudo', 'chmod', 'go+r', filename])
            if os.path.isdir(filename):
                # to be able to stat files down the tree
                # where someone else is owner of dir
                subprocess.call(['sudo', 'chmod', 'o+x', filename])
        if os.path.isdir(filename):
            return os.stat(filename).st_size, 'directory'
        mime_type = magic.from_file(filename_raw_utf8, mime=True)
        size = os.stat(filename).st_size
        return size, mime_type


    def list_files(self, path, tenant, root):
        """
        List a directory.

        Listing the export directory requires changing folder
        and file modes in order to stat inodes.

        Listing the import directory has its own special semantics.
        The requestor is only allowed to list those group folders
        which intersect with their group memberships. At the top
        level folder, only folders are allowed.

        When the backend does not have has_posix_ownership and/or
        group logic, the API owns everything, and listing is simple.

        Returns
        -------
        dict

        """
        current_page = 0
        pagination_value = 100
        try:
            current_page = int(self.get_query_argument('page'))
            pagination_value = int(self.get_query_argument('per_page'))
        except HTTPError as e:
            pass # use default value
        except ValueError:
            self.set_status(400)
            self.message = 'next values must be integers'
            raise Exception
        if current_page < 0:
            self.set_status(400)
            self.message = 'next values are natural numbers'
            raise Exception
        if pagination_value > 1000:
            self.set_status(400)
            self.message = 'per_page cannot exceed 1000'
            raise Exception
        # arbitrary order
        # if not returning what you want
        # then try next page
        dir_map = os.scandir(path)
        paginate = False
        files = []
        start_at = (current_page * pagination_value) - 1
        stop_at = start_at + pagination_value
        # only materialise the necessary entries
        for num, entry in enumerate(dir_map):
            if num <= start_at:
                continue
            elif num <= stop_at and num >= start_at:
                files.append(entry)
            elif num == stop_at + 1:
                paginate = True
                break # there is more
        if len(files) == 0:
            self.write({'files': [], 'page': None})
        else:
            if paginate and not current_page:
                next_page = 1
            elif paginate:
                next_page = str(current_page) + 1
            else:
                next_page = None
            baseuri = self.request.uri.split('?')[0]
            nextref = f'{baseuri}?next={next_page}' if next_page else None
            if self.export_max and len(files) > self.export_max:
                self.set_status(400)
                self.message = 'too many files, create a zip archive'
                raise Exception
            names = []
            times = []
            exportable = []
            reasons = []
            sizes = []
            mimes = []
            owners = []
            if not self.group_config['enabled']:
                default_owner = options.default_file_owner.replace(options.tenant_string_pattern, tenant)
                for file in files:
                    filepath = file.path
                    try:
                        size, mime_type = self.get_file_metadata(filepath)
                        status = self.enforce_export_policy(self.export_policy, filepath, tenant, size, mime_type)
                        if status:
                            reason = None
                        else:
                            reason = self.message
                    except Exception as e:
                        logging.error(e)
                        logging.error('could not enforce export policy when listing dir')
                        raise Exception
                    path_stat = file.stat()
                    latest = path_stat.st_mtime
                    date_time = str(datetime.datetime.fromtimestamp(latest).isoformat())
                    if self.has_posix_ownership:
                        try:
                            owner = pwd.getpwuid(path_stat.st_uid).pw_name
                        except KeyError:
                            try:
                                default_owner_id = pwd.getpwnam(default_owner).pw_uid
                                group_id = path_stat.st_gid
                                os.chown(group_folder, file_api_user_id, group_id)
                                owner = default_owner
                            except (KeyError, Exception) as e:
                                logging.error(e)
                                logging.error(f'could not reset owner of {filepath} to default')
                                owner = 'nobody'
                    else:
                        owner = options.api_user
                    names.append(os.path.basename(filepath))
                    times.append(date_time)
                    exportable.append(status)
                    reasons.append(reason)
                    sizes.append(size)
                    mimes.append(mime_type)
                    owners.append(owner)
            else: # then it is the TSD import dir
                group_memberships = self.claims.get('groups')
                if root:
                    for file in files:
                        if file.name in group_memberships:
                            names.append(os.path.basename(file.path))
                            times.append(None)
                            exportable.append(False)
                            reasons.append(None)
                            sizes.append(None)
                            mimes.append(None)
                            owners.append(None)
                else:
                    for file in files:
                        names.append(file.name)
                        # until someone asks for sync to check
                        # server-side file size, and mtime
                        # getting file metadata is unsupported
                        times.append(None)
                        exportable.append(False)
                        reasons.append(None)
                        sizes.append(None)
                        mimes.append(None)
                        owners.append(None)
            file_info = []
            for f, t, e, r, s, m, o in zip(names, times, exportable, reasons, sizes, mimes, owners):
                href = '%s/%s' % (self.request.uri, url_escape(f))
                file_info.append({'filename': f,
                                  'size': s,
                                  'modified_date': t,
                                  'href': href,
                                  'exportable': e,
                                  'reason': r,
                                  'mime-type': m,
                                  'owner': o})
            logging.info('%s listed %s', self.requestor, path)
            self.write({'files': file_info, 'page': nextref})


    def compute_etag(self):
        """
        If there is a file resource, compute the Etag header.
        Custom values: md5sum of string value of last modified
        time of file. Client can get this value before staring
        a download, and then if they need to resume for some
        reason, check that the resource has not changed in
        the meantime. It is also cheap to compute.

        Note, since this is a strong validator/Etag, nginx will
        strip it from the headers if it has been configured with
        gzip compression for HTTP responses.

        """
        try:
            if self.filepath:
                mtime = os.stat(self.filepath).st_mtime
                etag = hashlib.md5(str(mtime).encode('utf-8')).hexdigest()
                return etag
        except (Exception, AttributeError) as e:
            return None
        else:
            return None


    @gen.coroutine
    def get(self, tenant, filename=None):
        """
        List the export dir, or serve a file, asynchronously.

        1. check token claims
        2. check the tenant

        If listing the dir:

        3. run the list_files method

        If serving a file:

        3. check the filename
        4. check that file exists
        5. enforce the export policy
        6. check if a byte range is being requested
        6. set the mime type
        7. serve the bytes requested (explicitly, or implicitly), chunked

        """
        self.message = 'Unknown error, please contact TSD'
        try:
            assert options.valid_tenant.match(tenant)
            self.path = self.export_dir
            if not filename or os.path.isdir(f'{self.path}/{self.resource}'):
                if not self.allow_list:
                    self.message = 'Method not allowed'
                    self.set_status(403)
                    raise Exception
                if filename and os.path.isdir(f'{self.path}/{self.resource}'):
                    self.path += f'/{self.resource}'
                root = True if self.resource == self.path else False
                self.list_files(self.path, tenant, root)
                return
            if not self.allow_export:
                self.message = 'Method not allowed'
                self.set_status(403)
                raise Exception
            try:
                secured_filename = check_filename(url_unescape(filename),
                                                  disallowed_start_chars=options.start_chars)
            except Exception as e:
                self.set_status(403)
                raise Exception
            self.filepath = '%s/%s' % (self.path, secured_filename)
            if not os.path.lexists(self.filepath):
                logging.error('%s tried to access a file that does not exist', self.requestor)
                self.set_status(404)
                self.message = 'File does not exist'
                raise Exception
            try:
                size, mime_type = self.get_file_metadata(self.filepath)
                status = self.enforce_export_policy(self.export_policy, self.filepath, tenant, size, mime_type)
                assert status
            except (Exception, AssertionError) as e:
                logging.error(e)
                self.set_status(400)
                raise Exception
            self.set_header('Content-Type', mime_type)
            if 'Range' not in self.request.headers:
                self.set_header('Content-Length', size)
                self.flush()
                fd = open(self.filepath, "rb")
                data = fd.read(self.CHUNK_SIZE)
                while data:
                    self.write(data)
                    yield self.flush()
                    data = fd.read(self.CHUNK_SIZE)
                fd.close()
            elif 'Range' in self.request.headers:
                if 'If-Range' in self.request.headers:
                    provided_etag = self.request.headers['If-Range']
                    computed_etag = self.compute_etag()
                    if provided_etag != computed_etag:
                        self.message = 'The resource has changed, get everything from the start again'
                        self.set_status(400)
                        raise Exception(self.message)
                # clients specify the range in terms of 0-based index numbers
                # with an inclusive interval: [start, end]
                client_byte_index_range = self.request.headers['Range']
                full_file_size = os.stat(self.filepath).st_size
                start_and_end = client_byte_index_range.split('=')[-1].split('-')
                if ',' in start_and_end:
                    self.set_status(405)
                    self.message = 'Multipart byte range requests not supported'
                    raise Exception(self.message)
                client_start = int(start_and_end[0])
                cursor_start = client_start
                try:
                    client_end = int(start_and_end[1])
                except Exception as e:
                    client_end = full_file_size - 1
                if client_end > full_file_size:
                    self.set_status(416)
                    raise Exception('Range request exceeds byte range of resource')
                # because clients provide 0-based byte indices
                # we must add 1 to calculate the desired amount to read
                bytes_to_read = client_end - client_start + 1
                self.set_header('Content-Length', bytes_to_read)
                self.flush()
                fd = open(self.filepath, "rb")
                fd.seek(cursor_start)
                sent = 0
                if self.CHUNK_SIZE > bytes_to_read:
                    self.CHUNK_SIZE = bytes_to_read
                data = fd.read(self.CHUNK_SIZE)
                sent = sent + self.CHUNK_SIZE
                while data and sent <= bytes_to_read:
                    self.write(data)
                    yield self.flush()
                    data = fd.read(self.CHUNK_SIZE)
                    sent = sent + self.CHUNK_SIZE
                fd.close()
            logging.info('user: %s, exported file: %s , with MIME type: %s', self.requestor, self.filepath, mime_type)
        except Exception as e:
            logging.error(e)
            logging.error(self.message)
            self.write({'message': self.message})
        finally:
            try:
                fd.close()
            except (OSError, UnboundLocalError) as e:
                pass
            self.finish()


    def head(self, tenant, filename):
        """
        Return information about a specific file.

        """
        self.message = 'Unknown error, please contact TSD'
        try:
            if not self.allow_info:
                self.message = 'Method not allowed'
                self.set_status(403)
                raise Exception
            assert options.valid_tenant.match(tenant)
            self.path = self.export_dir
            if not filename:
                raise Exception('No info to report')
            try:
                secured_filename = check_filename(url_unescape(filename),
                                                  disallowed_start_chars=options.start_chars)
            except Exception as e:
                raise Exception
            self.filepath = '%s/%s' % (self.path, secured_filename)
            if not os.path.lexists(self.filepath):
                logging.error(self.filepath)
                logging.error('%s tried to access a file that does not exist', self.requestor)
                self.set_status(404)
                self.message = 'File does not exist'
                raise Exception
            if os.path.isdir(self.filepath):
                self.set_status(403)
                self.message = 'Cannot perform HEAD on directory'
                raise Exception
            size, mime_type = self.get_file_metadata(self.filepath)
            status = self.enforce_export_policy(self.export_policy, self.filepath, tenant, size, mime_type)
            assert status
            logging.info('user: %s, checked file: %s , with MIME type: %s', self.requestor, self.filepath, mime_type)
            self.set_header('Content-Length', size)
            self.set_header('Accept-Ranges', 'bytes')
            self.set_status(200)
        except Exception as e:
            logging.error(e)
            logging.error(self.message)
            self.write({'message': self.message})
        finally:
            self.finish()


    def delete(self, tenant, filename):
        self.message = 'Unknown error, please contact TSD'
        try:
            if not self.allow_delete:
                self.message = 'Method not allowed'
                self.set_status(403)
                raise Exception
            try:
                self.authnz = self.process_token_and_extract_claims(
                    check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
                )
            except Exception:
                if not self.message:
                    self.message = 'Not authorized to delete data'
                self.set_status(401)
                raise Exception
            assert options.valid_tenant.match(tenant)
            # only TSD import dir which is not the same dir
            self.path = self.export_dir
            if not filename:
                raise Exception('No file to delete')
            try:
                secured_filename = check_filename(url_unescape(filename),
                                                  disallowed_start_chars=options.start_chars)
            except Exception as e:
                raise Exception
            self.filepath = '%s/%s' % (self.path, secured_filename)
            if not os.path.lexists(self.filepath):
                logging.error('%s tried to delete a file that does not exist', self.requestor)
                self.set_status(404)
                self.message = f'File does not exist {self.filepath}'
                raise Exception
            if os.path.isdir(self.filepath):
                self.set_status(403)
                self.message = 'Cannot perform DELETE on directory - delete files individually'
                raise Exception
            try:
                # Allow the file to be deleted by changing the rights temporary of the parent directory
                if self.has_posix_ownership:
                    subprocess.call(['sudo', 'chmod', 'o+w',  os.path.dirname(self.filepath)])

                os.remove(self.filepath)

                # Restoring the rights of the parent directory
                if self.has_posix_ownership:
                    subprocess.call(['sudo', 'chmod', 'o-w',  os.path.dirname(self.filepath)])
                self.message = 'Deleted %s' % self.filepath
            except OSError as e:
                self.set_status(500)
                self.message = 'Problem deleting %s' % self.filepath
                raise Exception
            logging.info('user: %s, deleted file: %s', self.requestor, self.filepath)
            self.set_status(200)
        except Exception as e:
            logging.error(self.message)
            self.write({'message': self.message})
        finally:
            self.finish({'message': self.message})

    def on_finish(self):
        if (self.request.method in ('GET', 'HEAD', 'DELETE')
            and not options.maintenance_mode_enabled):
            try:
                message_data = {
                    'path': None,
                    'requestor': self.requestor,
                    'group': None
                }
                self.handle_mq_publication(
                    mq_config=self.mq_config,
                    data=message_data
                )
            except Exception as e:
                logging.error(e)


class GenericTableHandler(AuthRequestHandler):

    """
    Manage data in generic db backend.

    """

    def create_table_name(self, table_name, suffix):
        return f'{table_name}_{suffix}'

    def get_uri_query(self, uri):
        if '?' in uri:
            return uri.split('?')[-1]
        else:
            return ''

    def initialize(self, backend):
        self.backend = backend
        self.tenant = tenant_from_url(self.request.uri)
        assert options.valid_tenant.match(self.tenant)
        self.endpoint = self.request.uri.split('/')[3]
        self.backend_config = options.config['backends']['dbs'][backend]
        self.dbtype = self.backend_config['db']['engine']
        self.table_structure = self.backend_config['table_structure']
        self.mq_config = self.backend_config.get('mq')
        self.check_tenant = self.backend_config.get('check_tenant')


    def prepare(self):
        try:
            self.error = None
            if options.maintenance_mode_enabled:
                self.set_status(503)
                self.error = 'Service temporarily unavailable'
                raise Exception(self.error)
            self.error = 'Unauthorized'
            self.rid_info = {'key': None, 'values': []}
            self.authnz = self.process_token_and_extract_claims(
                check_tenant=self.check_tenant if self.check_tenant is not None else options.check_tenant
            )
            if self.dbtype == 'sqlite':
                self.import_dir = self.backend_config['db']['path']
                self.tenant_dir = self.import_dir.replace(options.tenant_string_pattern, self.tenant)
                if self.backend == 'apps_tables':
                    app_name = self.request.uri.split('/')[4]
                    self.db_name = f'.{self.backend}_{app_name}.db'
                else:
                    self.db_name =  f'.{self.backend}.db'
                self.engine = sqlite_init(self.tenant_dir, name=self.db_name, builtin=True)
                self.db = SqliteBackend(self.engine, requestor=self.requestor)
            elif self.dbtype == 'postgres':
                self.db = PostgresBackend(options.pgpool, schema=self.tenant, requestor=self.requestor)
        except Exception as e:
            if self._status_code != 503:
                self.set_status(401)
                logging.error(e)
                logging.error(self.error)
            self.finish()


    def decrypt_nacl_data(self, data, headers):
        out = b''
        nacl_stream_buffer = b''
        try:
            nacl_nonce = options.sealed_box.decrypt(
                base64.b64decode(headers['Nacl-Nonce'])
            )
            nacl_key = options.sealed_box.decrypt(
                base64.b64decode(headers['Nacl-Key'])
            )
        except Exception as e:
            self.error = 'Could not decrypt Nacl headers'
            logging.error(e)
            logging.error(self.error)
            raise Exception
        try:
            nacl_chunksize = int(headers['Nacl-Chunksize'])
        except KeyError:
            self.error = 'Missing Nacl-Chunksize header - cannot decrypt data'
            logging.error(self.error)
            raise Exception
        if nacl_chunksize > options.max_nacl_chunksize:
            self.error = f'Nacl-Chunksize larger than max allowed: {options.max_nacl_chunksize}'
            raise Exception(self.error)
        for byte in data:
            nacl_stream_buffer += bytes([byte])
            if len(nacl_stream_buffer) % nacl_chunksize == 0:
                decrypted = libnacl.crypto_stream_xor(
                    nacl_stream_buffer,
                    nacl_nonce,
                    nacl_key
                )
                out += decrypted
                nacl_stream_buffer = b''
        if nacl_stream_buffer:
            decrypted = libnacl.crypto_stream_xor(
                nacl_stream_buffer,
                nacl_nonce,
                nacl_key
            )
            out += decrypted
        return out.decode()


    def set_resource_identifier_info(self, data):
        """
        When publising messages to rabbitmq, it is useful
        for queue consumers to have references to the specific
        resources that were created, modified or deleted.

        In the case where all information is contained in the URI,
        such as for GET, and DELETE, this function is superfluous.

        However, for both PUT and PATCH, resource references are
        contained in the request body. Clients can optionally
        provide information about which key(s) in the request
        data contain unique references to their data, by setting
        the Resource-Identifier header.

        This function will then put both the key, and the value(s)
        produced by using the key, in the payload of the rabbitmq
        message.  Downstream queue consumers can then use these
        references to fetch the target resources from the API.

        """
        rid_key = self.request.headers.get('Resource-Identifier')
        if rid_key:
            if isinstance(data, dict):
                rid_values = [data.get(rid_key)]
            elif isinstance(data, list):
                rid_values = []
                for entry in data:
                    rid_values.append(entry.get(rid_key))
            self.rid_info = {'key': rid_key, 'values': rid_values}


    @gen.coroutine
    def get(self, tenant, table_name=None):
        try:
            if not table_name:
                tables = self.db.tables_list()
                self.set_status(200)
                self.write({'tables': tables})
            else:
                if self.table_structure:
                    # describe sub-endpoints of tables
                    base_url = self.request.uri.split('?')[0]
                    for entry in self.table_structure:
                        if base_url.endswith(entry):
                            data_request = True
                            break
                        else:
                            data_request = False
                else:
                    data_request = True
                if not data_request:
                    self.set_status(200)
                    self.write({'data': self.table_structure})
                else:
                    suffixes = ['metadata', 'audit']
                    for suffix in suffixes:
                        if self.request.uri.split('?')[0].endswith(suffix):
                            table_name = self.create_table_name(table_name, suffix)
                    self.set_status(200)
                    self.set_header('Content-Type', 'application/json')
                    self.write('{"data": [')
                    self.flush()
                    first = True
                    query = self.get_uri_query(self.request.uri)
                    for row in self.db.table_select(table_name, query):
                        if not first:
                            self.write(',')
                        self.write(row)
                        self.flush()
                        first = False
                    self.write(']}')
                    self.flush()
        except Exception as e:
            logging.error(e)
            self.set_status(400)
            self.write({'message': self.error})


    def put(self, tenant, table_name):
        try:
            if self.request.headers.get('Content-Type') == 'application/json+nacl':
                new_data = self.decrypt_nacl_data(
                    self.request.body,
                    self.request.headers
                )
            else:
                new_data = self.request.body
            data = json_decode(new_data)
            self.set_resource_identifier_info(data)
            if self.request.uri.split('?')[0].endswith('metadata'):
                table_name = self.create_table_name(table_name, 'metadata')
            if self.request.uri.split('?')[0].endswith('audit'):
                self.set_status(403)
                self.error = 'Not allowed to write to audit tables'
                raise Exception(self.error)
            try:
                self.db.table_insert(table_name, data)
                self.set_status(201)
                self.write({'message': 'data stored'})
            except Exception as e:
                logging.error(e)
                raise Exception
        except Exception as e:
            logging.error(e)
            if not self._status_code == 403:
                self.set_status(400)
            self.write({'message': self.error})


    def patch(self, tenant, table_name):
        try:
            if self.request.uri.split('?')[0].endswith('metadata'):
                table_name = self.create_table_name(table_name, 'metadata')
            if self.request.uri.split('?')[0].endswith('audit'):
                self.set_status(403)
                self.error = 'Not allowed to write to audit tables'
                raise Exception(self.error)
            if self.request.headers.get('Content-Type') == 'application/json+nacl':
                new_data = self.decrypt_nacl_data(
                    self.request.body,
                    self.request.headers
                )
            else:
                new_data = self.request.body
            data = json_decode(new_data)
            self.set_resource_identifier_info(data)
            query = self.get_uri_query(self.request.uri)
            out = self.db.table_update(table_name, query, data)
            self.set_status(200)
            self.write({'data': 'data updated'})
        except Exception as e:
            logging.error(e)
            if not self._status_code == 403:
                self.set_status(400)
            self.write({'message': self.error})


    def delete(self, tenant, table_name):
        try:
            if self.request.uri.split('?')[0].endswith('metadata'):
                table_name = self.create_table_name(table_name, 'metadata')
            if self.request.uri.split('?')[0].endswith('audit'):
                self.set_status(403)
                self.error = 'Not allowed to delete from audit tables'
                raise Exception(self.error)
            query = self.get_uri_query(self.request.uri)
            data = self.db.table_delete(table_name, query)
            self.set_status(200)
            self.write({'data': data})
        except Exception as e:
            logging.error(e)
            if not self._status_code == 403:
                self.set_status(400)
            self.write({'message': self.error})


    def on_finish(self):
        try:
            if not options.maintenance_mode_enabled:
                message_data = {
                    'path': None,
                    'requestor': self.requestor,
                    'group': None,
                    'resource_identifier': self.rid_info
                }
                self.handle_mq_publication(
                    mq_config=self.mq_config,
                    data=message_data
                )
        except Exception as e:
            logging.error(e)


class HealthCheckHandler(RequestHandler):

    def head(self, tenant):
        self.set_status(200)
        self.write({'message': 'healthy'})


class NaclKeyHander(RequestHandler):

    def get(self, tenant):
        public_key = options.config.get('nacl_public').get('public')
        out = {
            'public_key': public_key,
            'encoding': 'base64',
            'alg': 'sealed_box,X25519,XSalsa20-Poly1305',
            'info': 'https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes',
            'exp': None,
            'usage': {
                'explanation':
                    "To be used in combination with encrypted stream " +
                     "(https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream) - " +
                     "clients are required to use the public_key to encrypt their secret key " +
                     "and nonce, and send this in the Nacl-Key, and Nacl-Nonce headers, along with the payload." +
                     "For more information see endpoint-specific docs.",
                'secret_stream_headers': {
                    'Nacl-Nonce': 'base64 encoded xchacha20poly1305 nonce',
                    'Nacl-Key': 'base64 encoded xchacha20poly1305 key',
                    'Nacl-Chunksize': 'string value: size of encrypted chunks, in bytes'
                },
                'max_bytes': {
                    'Nacl-Chunksize': options.max_nacl_chunksize,
                }
            }
        }
        self.write(out)

class RunTimeConfigurationHandler(RequestHandler):

    def post(self):
        try:
            action = url_escape(self.get_query_argument('maintenance'))
            assert action in ['on', 'off'], f'action: {action} not supported'
            if action == 'on':
                options.maintenance_mode_enabled = True
            elif action == 'off':
                options.maintenance_mode_enabled = False
            self.write({'maintenance_mode_enabled': options.maintenance_mode_enabled})
        except (Exception, AssertionError) as e:
            self.set_status(400)
            logging.error(e)

    def get(self):
        self.write({'maintenance_mode_enabled': options.maintenance_mode_enabled})


class Backends(object):

    default_routes = {
        'health': [
            ('/v1/(.*)/files/health', HealthCheckHandler),
        ],
        'runtime_configuration': [
            ('/v1/admin.*', RunTimeConfigurationHandler),
        ]
    }

    optional_routes = {
        'cluster': [
            ('/v1/(.*)/cluster/upload_stream', StreamHandler, dict(backend='cluster')),
            ('/v1/(.*)/cluster/upload_stream/(.*)', StreamHandler, dict(backend='cluster')),
            ('/v1/(.*)/cluster/stream', ProxyHandler, dict(backend='cluster', namespace='cluster', endpoint='stream')),
            ('/v1/(.*)/cluster/stream/(.*)', ProxyHandler, dict(backend='cluster', namespace='cluster', endpoint='stream')),
            ('/v1/(.*)/cluster/resumables', ResumablesHandler, dict(backend='cluster')),
            ('/v1/(.*)/cluster/resumables/(.*)', ResumablesHandler, dict(backend='cluster')),
            ('/v1/(.*)/cluster/export', ProxyHandler, dict(backend='cluster', namespace='cluster', endpoint='export')),
            ('/v1/(.*)/cluster/export/(.*)', ProxyHandler, dict(backend='cluster', namespace='cluster', endpoint='export')),
        ],
        'files_import': [
            ('/v1/(.*)/files/upload_stream', StreamHandler, dict(backend='files_import')),
            ('/v1/(.*)/files/upload_stream/(.*)', StreamHandler, dict(backend='files_import')),
            ('/v1/(.*)/files/stream', ProxyHandler, dict(backend='files_import', namespace='files', endpoint='stream')),
            ('/v1/(.*)/files/stream/(.*)', ProxyHandler, dict(backend='files_import', namespace='files', endpoint='stream')),
            ('/v1/(.*)/files/resumables', ResumablesHandler, dict(backend='files_import')),
            ('/v1/(.*)/files/resumables/(.*)', ResumablesHandler, dict(backend='files_import')),
        ],
        'files_export': [
            ('/v1/(.*)/files/export', ProxyHandler, dict(backend='files_export', namespace='files', endpoint='export')),
            ('/v1/(.*)/files/export/(.*)', ProxyHandler, dict(backend='files_export', namespace='files', endpoint='export')),
        ],
        'survey': [
            ('/v1/(.*)/survey/crypto/key', NaclKeyHander),
            ('/v1/(.*)/survey/([a-zA-Z_0-9]+/attachments.*)', ProxyHandler, dict(backend='survey', namespace='survey', endpoint=None)),
            ('/v1/(.*)/survey/resumables', ResumablesHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/resumables/(.*)', ResumablesHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/upload_stream/(.*)', StreamHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/([a-zA-Z_0-9]+)/metadata', GenericTableHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/([a-zA-Z_0-9]+)/submissions', GenericTableHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/([a-zA-Z_0-9]+)/audit', GenericTableHandler, dict(backend='survey')),
            ('/v1/(.*)/survey/([a-zA-Z_0-9]+)$', GenericTableHandler, dict(backend='survey')),
            ('/v1/(.*)/survey', GenericTableHandler, dict(backend='survey')),
        ],
        'form_data': [
            ('/v1/(.*)/files/upload', FormDataHandler, dict(backend='form_data')),
            ('/v1/(.*)/sns/(.*)/(.*)', SnsFormDataHandler, dict(backend='sns')),
        ],
        'store': [
            ('/v1/(.*)/store/upload_stream', StreamHandler, dict(backend='store')),
            ('/v1/(.*)/store/upload_stream/(.*)', StreamHandler, dict(backend='store')),
            ('/v1/(.*)/store/import', ProxyHandler, dict(backend='store', namespace='store', endpoint='import')),
            ('/v1/(.*)/store/import/(.*)', ProxyHandler, dict(backend='store', namespace='store', endpoint='import')),
            ('/v1/(.*)/store/resumables', ResumablesHandler, dict(backend='store')),
            ('/v1/(.*)/store/resumables/(.*)', ResumablesHandler, dict(backend='store')),
            ('/v1/(.*)/store/export', ProxyHandler, dict(backend='store', namespace='store', endpoint='export')),
            ('/v1/(.*)/store/export/(.*)', ProxyHandler, dict(backend='store', namespace='store', endpoint='export')),
        ],
        'apps_files' : [
            ('/v1/(.*)/apps/.+/resumables', ResumablesHandler, dict(backend='apps_files')),
            ('/v1/(.*)/apps/.+/resumables/(.*)', ResumablesHandler, dict(backend='apps_files')),
            ('/v1/(.*)/apps/upload_stream/(.*)',  StreamHandler, dict(backend='apps_files')),
            ('/v1/(.*)/apps/(.+/files.*)', ProxyHandler, dict(backend='apps_files', namespace='apps', endpoint=None)),
        ],
        'apps_tables': [
            ('/v1/(.*)/apps/(.+)/tables/audit', GenericTableHandler, dict(backend='apps_tables')),
            ('/v1/(.*)/apps/(.+)/tables/metadata', GenericTableHandler, dict(backend='apps_tables')),
            ('/v1/(.*)/apps/.+/tables/(.+)$', GenericTableHandler, dict(backend='apps_tables')),
        ]
    }

    database_backends = {
        'sqlite': SqliteBackend,
        'postgres': PostgresBackend
    }

    def __init__(self, config):

        self.config = config
        self.routes = []
        self.exchanges = {}

        print(colored(f'tsd-file-api, listening on port {options.port}', 'yellow'))

        print(colored('Loading default routes:', 'magenta'))
        for name, route_set in self.default_routes.items():
            for route in route_set:
                print(colored(f'- {route[0]}', 'yellow'))
                self.routes.append(route)

        print(colored('Loading backend configuration:', 'magenta'))
        for backend_set in self.config['backends']:
            for backend in options.config['backends'][backend_set]:
                if backend in self.optional_routes.keys():
                    print(colored(f'Initialising: {backend}', 'cyan'))
                    for route in self.optional_routes[backend]:
                        print(colored(f'- {route[0]}', 'yellow'))
                        self.routes.append(route)

        print(colored('Initialising database backends', 'magenta'))
        for name, backend in self.config['backends']['dbs'].items():
            db_backend = self.database_backends[backend['db']['engine']]
            if db_backend.generator_class.db_init_sql:
                print(colored(f"DB backend: {backend['db']['engine']}", 'cyan'))
                self.initdb(name)

        if self.config.get('rabbitmq', {}).get('enabled'):
            print(colored('Finding rabbitmq exchanges', 'magenta'))
            for backend_set in self.config['backends']:
                for name, backend in options.config['backends'][backend_set].items():
                    self.find_exchanges(name, backend)

    def initdb(self, name):
        engine_type = options.config['backends']['dbs'][name]['db']['engine']
        if engine_type == 'postgres':
            pool = postgres_init(options.config['backends']['dbs'][name]['db']['dbconfig'])
            define('pgpool', pool)
            db = PostgresBackend(pool)
            db.initialise()
        else:
            return

    def find_exchanges(self, name, backend_config):
        mq_config = backend_config.get('mq')
        if not mq_config:
            return
        print(
            colored(f'Backend: {name}, ', 'cyan'),
            colored(f'rabbitmq settings: {mq_config}', 'yellow')
        )
        existing_exchanges = []
        for name, config in self.exchanges.items():
            existing_exchanges.append(config.get('exchange'))
        if (not self.exchanges.get(name) and
            mq_config.get('exchange') not in existing_exchanges):
            self.exchanges[name] = mq_config


def main():
    tornado.log.enable_pretty_logging()
    backends = Backends(options.config)
    pika_client = (
        PikaClient(options.rabbitmq, backends.exchanges) if options.rabbitmq.get('enabled')
        else None
    )
    app = Application(
        backends.routes,
        **{'pika_client': pika_client, 'debug': options.debug}
    )
    app.listen(options.port, max_body_size=options.max_body_size)
    ioloop = IOLoop.instance()
    if pika_client:
        ioloop.add_timeout(time.time() + .1, pika_client.connect)
    ioloop.start()


if __name__ == '__main__':
    main()
