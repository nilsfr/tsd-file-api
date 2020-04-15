# -*- coding: utf-8 -*-
"""

Run this as: python -m tsdfileapi.tests.test_file_api test-config.yaml

-------------------------------------------------------------------------------

Exploring Transfer-Encoding: chunked with a minimal python client.

From: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding

Data is sent in a series of chunks. The Content-Length header is omitted in this
case and at the beginning of each chunk you need to add the length of the current
chunk in hexadecimal format, followed by '\r\n' and then the chunk itself, followed
by another '\r\n'.

The terminating chunk is a regular chunk, with the exception that its length is zero.
It is followed by the trailer, which consists of a (possibly empty) sequence of
entity header fields.

E.g.

HTTP/1.1 200 OK
Content-Type: text/plain
Transfer-Encoding: chunked

7\r\n
Mozilla\r\n
9\r\n
Developer\r\n
7\r\n
Network\r\n
0\r\n
\r\n

tornado
so with tornado it _just works_ - but not the naive impl
the async method write data to the file, while waiting for the rest
this is _exactly what the video streaming needs.
behind nginx you need to set the following:
proxy_http_version 1.1;
proxy_request_buffering off;

From bdarnell:
sending an error requires a little-used feature of HTTP called "100-continue".
If the client supports 100-continue (curl-based clients do by default for large POSTS;
most others don't. I don't know if curl uses 100-continue with chunked requests)
and the tornado service uses @stream_request_body, then sending an error response
from prepare() will be received by the client before the body is uploaded

On 100-continue:
https://tools.ietf.org/html/rfc7231#page-50

So the HTTP Client should implement this...
Some background on python2.7 and requests
https://github.com/kennethreitz/requests/issues/713

"""

# pylint tends to be too pedantic regarding docstrings - we can decide in code review
# pylint: disable=missing-docstring
# test names are verbose...
# pylint: disable=too-many-public-methods
# method names are verbose in tests
# pylint: disable=invalid-name

import base64
import json
import logging
import os
import random
import sys
import time
import unittest
import pwd
import uuid
import shutil
from datetime import datetime

from pretty_bad_protocol import gnupg
import requests
import yaml
from sqlalchemy.exc import OperationalError
from tsdapiclient import fileapi
from tornado.escape import url_escape

import pretty_bad_protocol._parsers
pretty_bad_protocol._parsers.Verify.TRUST_LEVELS["ENCRYPTION_COMPLIANCE_MODE"] = 23

# pylint: disable=relative-import
from tsdfileapi.auth import process_access_token
from tsdfileapi.tokens import gen_test_tokens, get_test_token_for_p12, gen_test_token_for_user
from tsdfileapi.db import session_scope, sqlite_init, postgres_init, SqliteBackend, \
               sqlite_session, PostgresBackend, postgres_session
from tsdfileapi.resumables import SerialResumable
from tsdfileapi.utils import sns_dir, md5sum, IllegalFilenameException
from tsdfileapi.pgp import _import_keys
from tsdfileapi.squril import SqliteQueryGenerator, PostgresQueryGenerator


def project_import_dir(config, tenant=None, backend=None, tenant_pattern=None):
    folder = config['backends']['disk'][backend]['import_path'].replace(tenant_pattern, tenant)
    return os.path.normpath(folder)


def lazy_file_reader(filename):
    with open(filename, 'rb') as f:
        while True:
            data = f.read(10)
            if not data:
                break
            else:
                yield data


class TestFileApi(unittest.TestCase):

    @classmethod
    def pgp_encrypt_and_base64_encode(cls, string):
        gpg = _import_keys(cls.config)
        encrypted = gpg.encrypt(string, cls.config['public_key_id'], armor=False)
        encoded = base64.b64encode(encrypted.data)
        return encoded

    @classmethod
    def setUpClass(cls):

        try:
            with open(sys.argv[1]) as f:
                cls.config = yaml.load(f, Loader=yaml.Loader)
        except Exception as e:
            print(e)
            print("Missing config file?")
            sys.exit(1)

        # includes p19 - a random project number for integration testing
        cls.test_project = cls.config['test_project']
        cls.maintenance_url = f"http://localhost:{str(cls.config['port'])}/v1/admin"
        cls.base_url = f"http://localhost:{str(cls.config['port'])}/v1/{cls.test_project}"
        cls.data_folder = os.path.expanduser(cls.config['data_folder'])
        cls.example_csv = os.path.normpath(cls.data_folder + '/example.csv')
        cls.an_empty_file = os.path.normpath(cls.data_folder + '/an-empty-file')
        cls.example_codebook = json.loads(
            open(os.path.normpath(cls.data_folder + '/example-ns.json')).read())
        cls.test_user = cls.config['test_user']
        cls.test_group = cls.config['test_group']
        cls.uploads_folder = project_import_dir(
            cls.config,
            cls.config['test_project'],
            backend='files_import',
            tenant_pattern=cls.config['tenant_string_pattern']
        )
        cls.uploads_folder_p12 = project_import_dir(
            cls.config,
            'p12',
            backend='files_import',
            tenant_pattern=cls.config['tenant_string_pattern']
        )
        cls.uploads_folder_survey = project_import_dir(
            cls.config,
            cls.config['test_project'],
            backend='survey',
            tenant_pattern=cls.config['tenant_string_pattern']
        )
        cls.test_sns_url = '/v1/{0}/sns/{1}/{2}'.format(
            cls.config['test_project'],
            cls.config['test_keyid'],
            cls.config['test_formid']
        )
        cls.test_sns_dir = cls.config['backends']['disk']['sns']['import_path']
        cls.test_formid = cls.config['test_formid']
        cls.test_keyid = cls.config['test_keyid']
        cls.sns_uploads_folder = sns_dir(
            cls.test_sns_dir,
            cls.config['test_project'],
            cls.test_sns_url,
            cls.config['tenant_string_pattern'],
            test=True
        )
        cls.store_import_folder = cls.config['backends']['disk']['store']['import_path'].replace('pXX', cls.config['test_project'])
        cls.apps_import_folder = cls.config['backends']['disk']['apps_files']['import_path'].replace('pXX', cls.config['test_project'])
        cls.verbose = cls.config.get('verbose')

        # endpoints
        cls.upload = cls.base_url + '/files/upload'
        cls.sns_upload = cls.base_url + '/sns/' + cls.config['test_keyid'] + '/' + cls.config['test_formid']
        cls.upload_sns_wrong = cls.base_url + '/sns/' + 'WRONG' + '/' + cls.config['test_formid']
        cls.stream = cls.base_url + '/files/stream'
        cls.upload_stream = cls.base_url + '/files/upload_stream'
        cls.export = cls.base_url + '/files/export'
        cls.resumables = cls.base_url + '/files/resumables'
        cls.cluster = cls.base_url + '/cluster/stream'
        cls.export_cluster = cls.base_url + '/cluster/export'
        cls.store_import = cls.base_url + '/store/import'
        cls.store_export = cls.base_url + '/store/export'
        cls.survey = cls.base_url + '/survey'
        cls.apps = cls.base_url + '/apps'
        cls.test_project = cls.test_project
        cls.tenant_string_pattern = cls.config['tenant_string_pattern']

        # auth tokens
        global TEST_TOKENS
        TEST_TOKENS = gen_test_tokens(cls.config)
        global P12_TOKEN
        P12_TOKEN = get_test_token_for_p12(cls.config)

        # example data
        cls.example_tar = os.path.normpath(cls.data_folder + '/example.tar')
        cls.example_tar_gz = os.path.normpath(cls.data_folder + '/example.tar.gz')
        cls.enc_symmetric_secret = cls.pgp_encrypt_and_base64_encode('tOg1qbyhRMdZLg==')
        cls.enc_hex_aes_key = cls.pgp_encrypt_and_base64_encode('ed6d4be32230db647bc63627f98daba0ac1c5d04ab6d1b44b74501ff445ddd97')
        cls.hex_aes_iv = 'a53c9b54b5f84e543b592050c52531ef'
        cls.example_aes = os.path.normpath(cls.data_folder + '/example.csv.aes')
        # tar -cf - totar3 | openssl enc -aes-256-cbc -a -pass file:<( echo $PW ) > example.tar.aes
        cls.example_tar_aes = os.path.normpath(cls.data_folder + '/example.tar.aes')
        # tar -cf - totar3 | gzip -9 | openssl enc -aes-256-cbc -a -pass file:<( echo $PW ) > example.tar.gz.aes
        cls.example_tar_gz_aes = os.path.normpath(cls.data_folder + '/example.tar.gz.aes')
        cls.example_gz = os.path.normpath(cls.data_folder + '/example.csv.gz')
        cls.example_gz_aes = os.path.normpath(cls.data_folder + '/example.csv.gz.aes')
        # openssl enc -aes-256-cbc -a -iv ${hex_aes_iv} -K ${hex_aes_key}
        cls.example_aes_with_key_and_iv = os.path.normpath(cls.data_folder + '/example.csv.aes-with-key-and-iv')
        cls.example_tar_aes_with_key_and_iv = os.path.normpath(cls.data_folder + '/example.tar.aes-with-key-and-iv')
        cls.example_tar_gz_aes_with_key_and_iv = os.path.normpath(cls.data_folder + '/example.tar.gz.aes-with-key-and-iv')
        cls.example_gz_aes_with_key_and_iv = os.path.normpath(cls.data_folder + '/example.csv.gz.aes-with-key-and-iv')
        # openssl enc -aes-256-cbc -iv ${hex_aes_iv} -K ${hex_aes_key}
        cls.example_binary_aes_with_key_and_iv = os.path.normpath(cls.data_folder + '/example.csv.binary-aes-with-key-and-iv')
        # resumables
        cls.resume_file1 = os.path.normpath(cls.data_folder + '/resume-file1')
        cls.resume_file2 = os.path.normpath(cls.data_folder + '/resume-file2')
        # filename tests
        cls.so_sweet = os.path.normpath(cls.data_folder + '/så_søt(1).txt')
        cls.red = os.path.normpath(cls.data_folder + '/rød_fil_(1).txt')
        cls.test_upload_id = '96c68dad-8dc5-4076-9569-92394001d42a'
        # TODO: make this configurable
        # do not dist with package
        cls.large_file = os.path.normpath(cls.data_folder + '/large-file')


    @classmethod
    def tearDownClass(cls):
        uploaded_files = os.listdir(cls.uploads_folder)
        test_files = os.listdir(cls.data_folder)
        today = datetime.fromtimestamp(time.time()).isoformat()[:10]
        file_list = ['streamed-example.csv', 'uploaded-example.csv',
                     'uploaded-example-2.csv', 'uploaded-example-3.csv',
                     'streamed-not-chunked', 'streamed-put-example.csv']
        for _file in uploaded_files:
            # TODO: eventually remove - still want to inspect them
            # manually while the data pipelines are in alpha
            if _file in ['totar', 'totar2', 'decrypted-aes.csv',
                         'totar3', 'totar4', 'ungz1', 'ungz-aes1',
                         'uploaded-example-2.csv', 'uploaded-example-3.csv']:
                continue
            if (_file in test_files) or (today in _file) or (_file in file_list):
                try:
                    os.remove(os.path.normpath(cls.uploads_folder + '/' + _file))
                except OSError as e:
                    logging.error(e)
                    continue
        sqlite_path = cls.uploads_folder + '/api-data.db'
        try:
            #os.remove(sqlite_path)
            pass
        except OSError:
            print('no tables to cleanup')
            return

    # Import Auth
    #------------

    def check_endpoints(self, headers):
        files = {'file': ('example.csv', open(self.example_csv))}
        for url in [self.upload, self.stream, self.upload_stream, self.upload]:
            resp = requests.put(url, headers=headers, files=files)
            self.assertEqual(resp.status_code, 401)
            resp = requests.post(url, headers=headers, files=files)
            self.assertEqual(resp.status_code, 401)
            resp = requests.patch(url, headers=headers, files=files)
            self.assertEqual(resp.status_code, 401)


    def test_D_timed_out_token_rejected(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['TIMED_OUT']}
        self.check_endpoints(headers)


    def test_E_unauthenticated_request_rejected(self):
        headers = {}
        self.check_endpoints(headers)


    # uploading files and streams
    #----------------------------

    # multipart formdata endpoint

    def remove(self, target_uploads_folder, newfilename):
        try:
            _file = os.path.normpath(target_uploads_folder + '/' + newfilename)
            os.remove(_file)
        except OSError:
            pass


    def mp_fd(self, newfilename, target_uploads_folder, url, method):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        f = open(self.example_csv)
        files = {'file': (newfilename, f)}
        if method == 'POST':
            self.remove(target_uploads_folder, newfilename)
            resp = requests.post(url, files=files, headers=headers)
        elif method == 'PATCH':
            # not going to remove here, since we need to test non-idempotent uploads
            resp = requests.patch(url, files=files, headers=headers)
        elif method == 'PUT':
            # not going to remove, need to check that it is idempotent
            resp = requests.put(url, files=files, headers=headers)
        f.close()
        return resp


    def check_copied_sns_file_exists(self, filename):
        file = (self.sns_uploads_folder + '/' + filename)
        hidden_file = file.replace(self.config['public_key_id'], '.tsd/' + self.config['public_key_id'])
        self.assertTrue(os.path.lexists(hidden_file))


    def t_post_mp(self, uploads_folder, newfilename, url):
        target = os.path.normpath(uploads_folder + '/' + newfilename)
        resp = self.mp_fd(newfilename, uploads_folder, url, 'POST')
        self.assertEqual(resp.status_code, 201)
        uploaded_file = os.path.normpath(uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_F_post_file_multi_part_form_data(self):
        self.t_post_mp(self.uploads_folder, 'uploaded-example.csv', self.upload)


    def test_F1_post_file_multi_part_form_data_sns(self):
        filename = 'sns-uploaded-example.csv'
        self.t_post_mp(self.sns_uploads_folder, filename, self.sns_upload)
        self.check_copied_sns_file_exists(filename)


    def test_FA_post_multiple_files_multi_part_form_data(self):
        newfilename1 = 'n1'
        newfilename2 = 'n2'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename1))
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename2))
        except OSError:
            pass
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.post(self.upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file1 = os.path.normpath(self.uploads_folder + '/' + newfilename1)
        uploaded_file2 = os.path.normpath(self.uploads_folder + '/' + newfilename2)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        resp2 = requests.post(self.upload, files=files, headers=headers)
        self.assertEqual(resp2.status_code, 201)
        self.assertNotEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertNotEqual(md5sum(self.example_csv), md5sum(uploaded_file2))


    def t_patch_mp(self, uploads_folder, newfilename, url):
        target = os.path.normpath(uploads_folder + '/' + newfilename)
        # need to get rid of previous round's file, if present
        self.remove(uploads_folder, newfilename)
        # first request - create a new file
        resp = self.mp_fd(newfilename, target, url, 'PATCH')
        self.assertEqual(resp.status_code, 201)
        uploaded_file = os.path.normpath(uploads_folder + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        # second request - PATCH should not be idempotent
        resp2 = self.mp_fd(newfilename, target, url, 'PATCH')
        self.assertEqual(resp2.status_code, 201)
        self.assertNotEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_G_patch_file_multi_part_form_data(self):
        self.t_patch_mp(self.uploads_folder, 'uploaded-example-2.csv', self.upload)


    def test_G1_patch_file_multi_part_form_data_sns(self):
        filename = 'sns-uploaded-example-2.csv'
        self.t_patch_mp(self.sns_uploads_folder, filename, self.sns_upload)
        self.check_copied_sns_file_exists(filename)


    def test_GA_patch_multiple_files_multi_part_form_data(self):
        newfilename1 = 'n3'
        newfilename2 = 'n4'
        try:
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename1))
            os.remove(os.path.normpath(self.uploads_folder + '/' + newfilename2))
        except OSError:
            pass
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.post(self.upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file1 = os.path.normpath(self.uploads_folder + '/' + newfilename1)
        uploaded_file2 = os.path.normpath(self.uploads_folder + '/' + newfilename2)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        resp2 = requests.patch(self.upload, files=files, headers=headers)
        self.assertEqual(resp2.status_code, 201)
        self.assertNotEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertNotEqual(md5sum(self.example_csv), md5sum(uploaded_file2))


    def t_put_mp(self, uploads_folder, newfilename, url):
        target = os.path.normpath(uploads_folder + '/' + newfilename)
        # remove file from previous round
        self.remove(uploads_folder, newfilename)
        # req1
        resp = self.mp_fd(newfilename, target, url, 'PUT')
        uploaded_file = os.path.normpath(uploads_folder + '/' + newfilename)
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        # req2
        resp2 = self.mp_fd(newfilename, target, url, 'PUT')
        self.assertEqual(resp2.status_code, 201)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_H_put_file_multi_part_form_data(self):
        self.t_put_mp(self.uploads_folder, 'uploaded-example-3.csv', self.upload)


    def test_H1_put_file_multi_part_form_data_sns(self):
        filename = 'sns-uploaded-example-3.csv'
        self.t_put_mp(self.sns_uploads_folder, filename, self.sns_upload)
        self.check_copied_sns_file_exists(filename)


    def test_HA_put_multiple_files_multi_part_form_data(self):
        newfilename1 = 'n5'
        newfilename2 = 'n6'
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put(self.upload, files=files, headers=headers)
        self.assertEqual(resp.status_code, 201)
        uploaded_file1 = os.path.normpath(self.uploads_folder + '/' + newfilename1)
        uploaded_file2 = os.path.normpath(self.uploads_folder + '/' + newfilename2)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))
        files = [('file', (newfilename1, open(self.example_csv, 'rb'), 'text/html')),
                 ('file', (newfilename2, open(self.example_csv, 'rb'), 'text/html'))]
        resp2 = requests.put(self.upload, files=files, headers=headers)
        self.assertEqual(resp2.status_code, 201)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file1))
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))


    def test_H4XX_when_no_keydir_exists(self):
        newfilename = 'new1'
        target = os.path.normpath(self.sns_uploads_folder + '/' + newfilename)
        resp1 = self.mp_fd(newfilename, target, self.upload_sns_wrong, 'PUT')
        resp2 = self.mp_fd(newfilename, target, self.upload_sns_wrong, 'POST')
        resp3 = self.mp_fd(newfilename, target, self.upload_sns_wrong, 'PATCH')
        self.assertEqual([resp1.status_code, resp2.status_code, resp3.status_code], [400, 400, 400])


    # streaming endpoint

    def test_I_put_file_to_streaming_endpoint_no_chunked_encoding_data_binary(self):
        newfilename = 'streamed-not-chunked'
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + self.test_group + '/' + newfilename)
        try:
            os.remove(uploaded_file)
        except OSError:
            pass
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'], 'Filename': newfilename}
        resp = requests.put(self.stream, data=open(self.example_csv), headers=headers)
        self.assertEqual(resp.status_code, 201)

        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))


    def test_K_put_stream_file_chunked_transfer_encoding(self):
        newfilename = 'streamed-put-example.csv'
        uploaded_file = os.path.normpath(self.uploads_folder + '/' + self.test_group + '/' + newfilename)
        try:
            os.remove(uploaded_file)
        except OSError:
            pass
        headers = {'Filename': 'streamed-put-example.csv',
                   'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Expect': '100-Continue'}
        resp = requests.put(self.stream, data=lazy_file_reader(self.example_csv), headers=headers)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        resp = requests.put(self.stream, data=lazy_file_reader(self.example_csv), headers=headers)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        self.assertEqual(resp.status_code, 201)


    # Informational
    #--------------

    def test_N_head_on_uploads_fails_when_it_should(self):
        resp1 = requests.head(self.upload)
        resp2 = requests.head(self.upload,
                              headers={'Authorization': 'Bearer ' + TEST_TOKENS['VALID']})
        self.assertEqual(resp1.status_code, 401)
        self.assertEqual(resp2.status_code, 400)


    def test_O_head_on_uploads_succeeds_when_conditions_are_met(self):
        files = {'file': ('example.csv', open(self.example_csv))}
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.head(self.upload, headers=headers, files=files)
        self.assertEqual(resp.status_code, 201)


    def test_P_head_on_stream_fails_when_it_should(self):
        pass


    def test_Q_head_on_stream_succeeds_when_conditions_are_met(self):
        pass

    # Support OPTIONS

    # Space issues

    def test_R_report_informative_error_when_running_out_space(self):
        pass
        # [Errno 28] No space left on device


    def test_W_create_and_insert_into_generic_table(self):
        # TODO: harden these tests - check return values
        data = [
            {'key1': 7, 'key2': 'bla', 'id': random.randint(0, 1000000)},
            {'key1': 99, 'key3': False, 'id': random.randint(0, 1000000)}
        ]
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put(self.base_url + '/tables/generic/mytest1',
                             data=json.dumps(data), headers=headers)
        self.assertEqual(resp.status_code, 201)
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Accept': 'text/csv'}
        resp = requests.get(self.base_url + '/tables/generic/mytest1', headers=headers)
        self.assertTrue(resp.status_code in [200, 201])


    def use_generic_table(self, app_route, url_tokens_method):
        methods = {
            'GET': requests.get,
            'PUT': requests.put,
            'DELETE': requests.delete
        }
        for url, token, method in url_tokens_method:
            headers = {'Authorization': 'Bearer ' + TEST_TOKENS[token]}
            full_url = self.base_url + app_route + url
            resp = methods[method](full_url, headers=headers)
            print(resp.text)
            self.assertTrue(resp.status_code in [200, 201])


    def test_X_use_generic_table(self):
        # TODO: harden these tests - check return values
        generic_url_tokens_method = [
            ('', 'VALID', 'GET'),
            ('/mytest1', 'EXPORT', 'GET'),
            ('/mytest1?select=key1&where=key2=eq.bla&order=key1.desc', 'EXPORT', 'GET'),
            ('/mytest1', 'EXPORT', 'GET'),
            ('/mytest1?where=key1=eq.99', 'ADMIN', 'DELETE'),
            ('/mytest1', 'EXPORT', 'GET'),
            ('/mytest1?where=key1=not.is.null', 'ADMIN', 'DELETE'),
        ]
        for app, acl in [('/tables/generic', generic_url_tokens_method)]:
            self.use_generic_table(app, acl)
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.patch(
            self.base_url + '/tables/generic/mytest1?set=key1&where=key2=eq.bla',
            data=json.dumps({'key1': 1000}),
            headers=headers)
        self.assertEqual(resp.status_code, 200)


    def test_XXX_nettskjema_backend(self):
        data = [
            {'key1': 7, 'key2': 'bla', 'id': random.randint(0, 1000000)},
            {'key1': 99, 'key3': False, 'id': random.randint(0, 1000000)}
        ]
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        # add data to a table
        resp = requests.put(
            self.base_url + '/survey/123456/submissions',
            data=json.dumps(data),
            headers=headers
        )
        self.assertEqual(resp.status_code, 201)
        # audit functionality
        resp = requests.patch(
            f'{self.survey}/123456/submissions?set=key1&where=key2=eq.bla',
            headers=headers,
            data=json.dumps({'key1': 5})
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(
            f'{self.survey}/123456/audit',
            headers=headers
        )
        resp = requests.delete(
            f'{self.survey}/123456/audit',
            headers=headers
        )
        self.assertEqual(resp.status_code, 403)
        # metadata functionality
        resp = requests.put(
            self.base_url + '/survey/123456/metadata',
            data=json.dumps(data),
            headers=headers
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            self.base_url + '/survey/123456/metadata',
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            self.base_url + '/survey/123456/metadata',
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        # check endpoint overview
        resp = requests.get(self.base_url + '/survey', headers=headers)
        data = json.loads(resp.text)
        self.assertTrue('123456' in data['tables'])
        self.assertEqual(resp.status_code, 200)
        # get data
        resp = requests.get(self.base_url + '/survey/123456', headers=headers)
        data = json.loads(resp.text)
        self.assertTrue('metadata' in data['data'])
        self.assertTrue('submissions' in data['data'])
        self.assertTrue('attachments' in data['data'])
        # perform some queries
        nettskjema_url_tokens_method = [
            ('/123456/submissions', 'ADMIN', 'GET'),
            ('/123456/submissions?select=key1&where=key2=eq.bla&order=key1.desc', 'ADMIN', 'GET'),
            ('/123456/submissions', 'ADMIN', 'GET'),
            ('/123456/submissions?where=key1=eq.99', 'ADMIN', 'DELETE'),
            ('/123456/submissions', 'ADMIN', 'GET'),
            ('/123456/submissions?where=key1=not.is.null', 'ADMIN', 'DELETE'),
        ]
        for app, acl in [('/survey', nettskjema_url_tokens_method)]:
            self.use_generic_table(app, acl)
        # attachments
        file = url_escape('some-survey-attachment.txt')
        resp = requests.put(
            f'{self.survey}/123456/attachments/{file}',
            data=lazy_file_reader(self.so_sweet),
            headers=headers
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f'{self.survey}/123456/attachments/{file}',
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)


    def test_XXX_load(self):
        numrows = 250000 # responses per survey
        numkeys = 1500 # questions per survey

        print('generating test data')
        pool = postgres_init(self.config['backends']['postgres']['dbconfig'])
        db = PostgresBackend(pool, schema='p11')
        for i in range(numrows):
            row = {}
            for j in range(numkeys):
                key = f'k{j}'
                row[key] = j
            uid = str(uuid.uuid4())
            row['id'] = uid
            # insert row
            db.table_insert('loadtest', row)
            total = i
            if i % (numrows/10.0) == 0:
                print('{} rows generated'.format(total))
                total += total

        # sqlite findings:
        # ~ 10gb of data in sqlite
        # on localhost, fetching everything:
        # real 0m48.339s
        # in a json file, that is 4.7gb

        # postgres findings:
        # on localhost, fetching everything:
        # real    4m21.898s
        # CPU intensive, memory fine

    # More Authn+z
    # ------------

    def test_Y_invalid_project_number_rejected(self):
        data = {'submission_id':11, 'age':193}
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put('http://localhost:' + str(self.config['port']) + '/p12-2193-1349213*&^/tables/generic/form_63332',
                             data=json.dumps(data), headers=headers)
        self.assertEqual(resp.status_code, 404)


    def test_Z_token_for_other_project_rejected(self):
        data = {'submission_id':11, 'age':193}
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['WRONG_PROJECT']}
        resp = requests.put(self.base_url + '/survey/63332/submissions',
                             data=json.dumps(data), headers=headers)
        self.assertEqual(resp.status_code, 401)


    # Handling custom content-types, on-the-fly
    # -----------------------------------------

    # Directories:
    # -----------
    # tar           -> untar
    # tar.gz        -> decompress, untar
    # tar.aes       -> decrypt, untar
    # tar.gz.aes    -> decrypt, uncompress, untar

    # Files:
    # -----
    # aes           -> decrypt
    # gz            -> uncompress
    # gz.aes        -> decrypt, uncompress

    def test_Za_stream_tar_without_custom_content_type_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp1 = requests.put(self.stream + '/example.tar', data=lazy_file_reader(self.example_tar),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # checksum comparison

    def test_Zb_stream_tar_with_custom_content_type_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar'}
        resp1 = requests.put(self.stream + '/totar', data=lazy_file_reader(self.example_tar),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Zc_stream_tar_gz_with_custom_content_type_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar.gz'}
        resp1 = requests.put(self.stream + '/totar2', data=lazy_file_reader(self.example_tar_gz),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Zd_stream_aes_with_custom_content_type_decrypt_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/aes',
                   'Aes-Key': self.enc_symmetric_secret}
        resp1 = requests.put(self.stream + '/decrypted-aes.csv', data=lazy_file_reader(self.example_aes),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        with open(self.uploads_folder + '/' + self.test_group + '/decrypted-aes.csv', 'r') as uploaded_file:
            self.assertEqual('x,y\n4,5\n2,1\n', uploaded_file.read())

    def test_Zd0_stream_aes_with_iv_and_custom_content_type_decrypt_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/aes',
                   'Aes-Key': self.enc_hex_aes_key,
                   'Aes-Iv': self.hex_aes_iv}
        resp1 = requests.put(self.stream + '/decrypted-aes2.csv',
                             data=lazy_file_reader(self.example_aes_with_key_and_iv),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        with open(self.uploads_folder + '/' + self.test_group + '/decrypted-aes2.csv', 'r') as uploaded_file:
            self.assertEqual('x,y\n4,5\n2,1\n', uploaded_file.read())

    def test_Zd1_stream_binary_aes_with_iv_and_custom_content_type_decrypt_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/aes-octet-stream',
                   'Aes-Key': self.enc_hex_aes_key,
                   'Aes-Iv': self.hex_aes_iv}
        resp1 = requests.put(self.stream + '/decrypted-binary-aes.csv',
                             data=lazy_file_reader(self.example_binary_aes_with_key_and_iv),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        with open(self.uploads_folder + '/' + self.test_group + '/decrypted-binary-aes.csv', 'r') as uploaded_file:
            self.assertEqual('x,y\n4,5\n2,1\n', uploaded_file.read())

    def test_Ze_stream_tar_aes_with_custom_content_type_decrypt_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar.aes',
                   'Aes-Key': self.enc_symmetric_secret}
        resp1 = requests.put(self.stream + '/totar3', data=lazy_file_reader(self.example_tar_aes),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Ze0_stream_tar_aes_with_iv_and_custom_content_type_decrypt_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar.aes',
                   'Aes-Key': self.enc_hex_aes_key,
                   'Aes-Iv': self.hex_aes_iv}
        resp1 = requests.put(self.stream+'/totar',
                             data=lazy_file_reader(self.example_tar_aes_with_key_and_iv),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Zf_stream_tar_aes_with_custom_content_type_decrypt_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar.gz.aes',
                   'Aes-Key': self.enc_symmetric_secret}
        resp1 = requests.put(self.stream + '/totar4', data=lazy_file_reader(self.example_tar_gz_aes),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Zf0_stream_tar_aes_with_iv_and_custom_content_type_decrypt_untar_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/tar.gz.aes',
                   'Aes-Key': self.enc_hex_aes_key,
                   'Aes-Iv': self.hex_aes_iv}
        resp1 = requests.put(self.stream + '/totar2', data=lazy_file_reader(self.example_tar_gz_aes_with_key_and_iv),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # check contents

    def test_Zg_stream_gz_with_custom_header_decompress_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/gz'}
        resp1 = requests.put(self.stream + '/ungz1', data=lazy_file_reader(self.example_gz),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        with open(self.uploads_folder + '/' + self.test_group + '/ungz1', 'r') as uploaded_file:
           self.assertEqual('x,y\n4,5\n2,1\n', uploaded_file.read())


    def test_Zh_stream_gz_aes_with_custom_header_decompress_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/gz.aes',
                   'Aes-Key': self.enc_symmetric_secret}
        resp1 = requests.put(self.stream + '/ungz-aes1', data=lazy_file_reader(self.example_gz_aes),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)
        # This ought to work, but does not
        with open(self.uploads_folder + '/' + self.test_group + '/ungz-aes1', 'r') as uploaded_file:
            self.assertEqual('x,y\n4,5\n2,1\n', uploaded_file.read())


    def test_Zh0_stream_gz_with_iv_and_custom_header_decompress_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Content-Type': 'application/gz.aes',
                   'Aes-Key': self.enc_hex_aes_key,
                   'Aes-Iv': self.hex_aes_iv}
        resp1 = requests.put(self.stream + '/ungz-aes1', data=lazy_file_reader(self.example_gz_aes_with_key_and_iv),
                             headers=headers)
        self.assertEqual(resp1.status_code, 201)

    def test_ZA_choosing_file_upload_directories_based_on_tenant_works(self):
        newfilename = 'uploaded-example-p12.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder_p12 + '/' + newfilename))
        except OSError:
            pass
        headers = {'Authorization': 'Bearer ' + P12_TOKEN}
        files = {'file': (newfilename, open(self.example_csv))}
        # remove hard-coded port from this, and similar tests
        resp1 = requests.post('http://localhost:' + str(self.config['port']) + '/v1/p12/files/upload', files=files, headers=headers)
        self.assertEqual(resp1.status_code, 201)
        uploaded_file = os.path.normpath(self.uploads_folder_p12 + '/' + newfilename)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file))
        newfilename2 = 'streamed-put-example-p12.csv'
        try:
            os.remove(os.path.normpath(self.uploads_folder_p12 + '/p12-member-group/' + newfilename2))
        except OSError:
            pass
        headers2 = {'Filename': 'streamed-put-example-p12.csv',
                   'Authorization': 'Bearer ' + P12_TOKEN,
                   'Expect': '100-Continue'}
        resp2 = requests.put('http://localhost:' + str(self.config['port']) + '/v1/p12/files/stream',
                            data=lazy_file_reader(self.example_csv), headers=headers2)
        self.assertEqual(resp2.status_code, 201)
        uploaded_file2 = os.path.normpath(self.uploads_folder_p12 + '/p12-member-group/' + newfilename2)
        self.assertEqual(md5sum(self.example_csv), md5sum(uploaded_file2))

    def test_ZB_sns_folder_logic_is_correct(self):
        # lowercase in key id
        self.assertRaises(Exception, sns_dir, self.test_sns_dir,
                         'p11', '/v1/p11/sns/255cE5ED50A7558B/98765', self.tenant_string_pattern)
        # too long but still valid key id
        self.assertRaises(Exception, sns_dir, self.test_sns_dir,
                         'p11', '/v1/p11/sns/255CE5ED50A7558BXIJIJ87878/98765', self.tenant_string_pattern)
        # non-numeric formid
        self.assertRaises(Exception, sns_dir, self.test_sns_dir,
                         'p11', '255CE5ED50A7558B', '99999-%$%&*', self.tenant_string_pattern)
        # note: /tsd/p11/data/durable _must_ exist for this test to pass
        self.assertEqual(sns_dir(self.test_sns_dir, 'p11', self.test_sns_url, self.tenant_string_pattern),
                         '/tsd/p11/data/durable/nettskjema-submissions/{0}/{1}'.format(self.test_keyid, self.test_formid))
        try:
            os.rmdir('/tsd/p11/data/durable/nettskjema-submissions/255CE5ED50A7558B/98765')
            os.rmdir('/tsd/p11/data/durable/nettskjema-submissions/255CE5ED50A7558B')
        except OSError:
            pass

    def test_ZC_setting_ownership_based_on_user_works(self):
        token = gen_test_token_for_user(self.config, self.test_user)
        headers = {'Authorization': 'Bearer ' + token,
                   'Filename': 'testing-chowner.txt'}
        resp = requests.put(self.stream,
                            data=lazy_file_reader(self.example_gz_aes),
                            headers=headers)
        intended_owner = pwd.getpwnam(self.test_user).pw_uid
        effective_owner = os.stat(self.uploads_folder + '/' + self.test_group + '/testing-chowner.txt').st_uid
        self.assertEqual(intended_owner, effective_owner)

    def test_ZD_cannot_upload_empty_file_to_sns(self):
        files = {'file': ('an-empty-file', open(self.an_empty_file))}
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put(self.sns_upload,
                            files=files,
                            headers=headers)
        self.assertEqual(resp.status_code, 400)

    # client-side specification of groups

    def test_ZE_stream_works_with_client_specified_group(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Expect': '100-Continue'}
        url = self.stream + '/streamed-example-with-group-spec.csv?group=p11-member-group'
        resp = requests.put(url,
                            data=lazy_file_reader(self.example_csv),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)

    def test_ZF_stream_does_not_work_with_client_specified_group_wrong_tenant(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Expect': '100-Continue'}
        url = self.stream + '/streamed-example-with-group-spec.csv?group=p12-member-group'
        resp = requests.post(url,
                             data=lazy_file_reader(self.example_csv),
                             headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_ZG_stream_does_not_work_with_client_specified_group_nonsense_input(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Expect': '100-Continue'}
        url = self.stream + '/streamed-example-with-group-spec.csv?group=%2Fusr%2Fbin%2Fecho%20%24PATH'
        resp = requests.post(url,
                             data=lazy_file_reader(self.example_csv),
                             headers=headers)
        self.assertEqual(resp.status_code, 401)

    def test_ZH_stream_does_not_work_with_client_specified_group_not_a_member(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID'],
                   'Expect': '100-Continue'}
        url = self.stream + '/streamed-example-with-group-spec.csv?group=p11-data-group'
        resp = requests.post(url,
                             data=lazy_file_reader(self.example_csv),
                             headers=headers)
        self.assertEqual(resp.status_code, 401)

    # export


    def test_ZJ_export_file_restrictions_enforced(self):
        headers={'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        for name in ['/bin/bash -c', '!#/bin/bash', '!@#$%^&*()-+', '../../../p01/data/durable']:
            resp = requests.get(self.export + '/' + name, headers=headers)
            self.assertTrue(resp.status_code in [403, 404, 401])


    def test_ZK_export_list_dir_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp = requests.get(self.export, headers=headers)
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(data['files']), 3)
        self.assertTrue(len(data['files'][0].keys()), 3)


    def test_ZL_export_file_works(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['ADMIN']}
        resp = requests.get(self.export + '/file1', headers=headers)
        self.assertEqual(resp.text, u'some data\n')
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(self.export + '/' + url_escape('blå_fil_3_(v1).txt'), headers=headers)
        self.assertEqual(resp.text, u'even more data')
        self.assertEqual(resp.status_code, 200)

    # resumable uploads


    def start_new_resumable(self, filepath, chunksize=1, large_file=False, stop_at=None,
                            token=None, endpoint=None, uploads_folder=None):
        if not token:
            token = TEST_TOKENS['VALID']
        filename = os.path.basename(filepath)
        if not endpoint:
            endpoint = self.stream
        url = '%s/%s' % (endpoint, filename)
        resp = fileapi.initiate_resumable('', self.test_project, filepath,
                                          token, chunksize=chunksize, new=True, group=None,
                                          verify=False, dev_url=url, stop_at=stop_at)
        if stop_at:
            return resp['id']
        self.assertEqual(resp['max_chunk'], u'end')
        self.assertTrue(resp['id'] is not None)
        self.assertEqual(resp['filename'], filename)
        if not large_file:
            if not uploads_folder:
                uploads_folder = self.uploads_folder + '/' + self.test_group
            self.assertEqual(md5sum(filepath),
                md5sum(uploads_folder + '/' + filename))


    def test_ZM_resume_new_upload_works_is_idempotent(self):
        self.start_new_resumable(self.resume_file1, chunksize=5)


    def test_ZN_resume_works_with_upload_id_match(self):
        cs = 5
        proj = ''
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS['VALID']
        url = '%s/%s' % (self.resumables, filename)
        print('---> going to resume from chunk 2:')
        resp = fileapi.initiate_resumable(proj, self.test_project, filepath,
                                          token, chunksize=cs, new=False, group=None,
                                          verify=True, upload_id=upload_id, dev_url=url)
        self.assertEqual(resp['max_chunk'], u'end')
        self.assertTrue(resp['id'] is not None)
        self.assertEqual(resp['filename'], filename)
        self.assertTrue('key' in resp.keys())


    def test_ZO_resume_works_with_filename_match(self):
        print('test_ZO_resume_works_with_filename_match')
        cs = 5
        proj = ''
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS['VALID']
        url = '%s/%s' % (self.resumables, filename)
        print('---> going to resume from chunk 2:')
        resp = fileapi.initiate_resumable(proj, self.test_project, filepath,
                                          token, chunksize=cs, new=False, group=None,
                                          verify=True, upload_id=upload_id, dev_url=url)
        self.assertEqual(resp['max_chunk'], u'end')
        self.assertTrue(resp['id'] is not None)
        self.assertEqual(resp['filename'], filename)


    def test_ZP_resume_do_not_upload_if_md5_mismatch(self):
        cs = 5
        proj = ''
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        uploaded_chunk = self.uploads_folder + '/' + upload_id + '/' + filename + '.chunk.1'
        merged_file = self.uploads_folder + '/' + filename + '.' + upload_id
        # manipulate the data to force an md5 mismatch
        with open(uploaded_chunk, 'wb+') as f:
            f.write(b'ffff\n')
        with open(merged_file, 'wb+') as f:
            f.write(b'ffff\n')
        token = TEST_TOKENS['VALID']
        url = '%s/%s' % (self.resumables, filename)
        print('---> resume should fail:')
        # now this _should_ start a new upload due to md5 mismatch
        resp = fileapi.initiate_resumable(proj, self.test_project, filepath,
                                          token, chunksize=cs, new=False, group=None,
                                          verify=True, upload_id=upload_id, dev_url=url)
        self.assertEqual(resp, None)
        res = SerialResumable(self.uploads_folder, 'p11-import_user')
        res._db_remove_completed_for_owner(upload_id)


    def test_ZR_cancel_resumable(self):
        cs = 5
        proj = ''
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=1)
        token = TEST_TOKENS['VALID']
        # TODO: use client once implemented
        url = '%s/%s?id=%s' % (self.resumables, filename, upload_id)
        resp = requests.delete(url, headers={'Authorization': 'Bearer ' + token})
        self.assertEqual(resp.status_code, 200)
        uploaded_folder = self.uploads_folder + '/' + upload_id
        merged_file = self.uploads_folder + '/' + filename + '.' + upload_id
        try:
            shutil.rmtree(uploaded_folder)
            os.remove(merged_file)
        except OSError:
            pass


    def test_ZS_recovering_inconsistent_data_allows_resume_from_previous_chunk(self):
        proj = ''
        token = TEST_TOKENS['VALID']
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        cs = 5
        upload_id = self.start_new_resumable(filepath, chunksize=cs, stop_at=2)
        url = '%s/%s' % (self.resumables, filename)
        merged_file = self.uploads_folder + '/' + filename + '.' + upload_id
        with open(merged_file, 'ab') as f:
            f.truncate(cs + (cs/2))
        # this should trigger data recovery, and restart the resumable at chunk1
        print('---> going to resume from chunk 3, after data recovery:')
        resp = fileapi.initiate_resumable(proj, self.test_project, filepath,
                                          token, chunksize=cs, new=False, group=None,
                                          verify=True, upload_id=upload_id, dev_url=url)
        self.assertEqual(resp['max_chunk'], u'end')
        self.assertTrue(resp['id'] is not None)
        self.assertEqual(resp['filename'], filename)


    def test_ZT_list_all_resumables(self):
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        cs = 5
        upload_id1 = self.start_new_resumable(filepath, chunksize=cs, stop_at=2)
        upload_id2 = self.start_new_resumable(filepath, chunksize=cs, stop_at=3)
        token = TEST_TOKENS['VALID']
        resp = requests.get(self.resumables, headers={'Authorization': 'Bearer ' + token})
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        uploaded_folder1 = self.uploads_folder + '/' + upload_id1
        uploaded_folder2 = self.uploads_folder + '/' + upload_id2
        merged_file1 = self.uploads_folder + '/' + filename + '.' + upload_id1
        merged_file2 = self.uploads_folder + '/' + filename + '.' + upload_id2
        try:
            shutil.rmtree(uploaded_folder1)
            shutil.rmtree(uploaded_folder2)
            os.remove(merged_file1)
            os.remove(merged_file2)
            res = SerialResumable(self.uploads_folder, 'p11-import_user')
            res._db_remove_completed_for_owner(upload_id1)
            res._db_remove_completed_for_owner(upload_id2)
        except OSError:
            pass


    def test_ZU_sending_uneven_chunks_resume_works(self):
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id1 = self.start_new_resumable(filepath, chunksize=3, stop_at=1)
        url = '%s/%s' % (self.resumables, filename)
        token = TEST_TOKENS['VALID']
        print('---> going to resume from chunk 2, with a new chunk size:')
        resp = fileapi.initiate_resumable('', self.test_project, filepath,
                                          token, chunksize=4, new=False, group=None,
                                          verify=True, dev_url=url, upload_id=upload_id1)
        self.assertEqual(md5sum(filepath),
                md5sum(self.uploads_folder + '/' + self.test_group + '/' + filename))
        uploaded_folder1 = self.uploads_folder + '/' + upload_id1
        merged_file1 = self.uploads_folder + '/' + filename + '.' + upload_id1
        try:
            shutil.rmtree(uploaded_folder1)
            os.remove(merged_file1)
            res = SerialResumable(self.uploads_folder, 'p11-import_user')
            res._db_remove_completed_for_owner(upload_id1)
        except OSError:
            pass


    def test_ZV_resume_chunk_order_enforced(self):
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        upload_id = self.start_new_resumable(filepath, chunksize=3, stop_at=2)
        url = '%s/%s?id=%s&chunk=2' % (self.stream, filename, upload_id)
        token = TEST_TOKENS['VALID']
        resp = requests.patch(url, headers={'Authorization': 'Bearer ' + token},
                              data='dddd\n')
        self.assertEqual(resp.status_code, 400)
        url = '%s/%s?id=%s&chunk=4' % (self.stream, filename, upload_id)
        resp = requests.patch(url, headers={'Authorization': 'Bearer ' + token},
                              data='dddd\n')
        self.assertEqual(resp.status_code, 400)
        uploaded_folder = self.uploads_folder + '/' + upload_id
        merged_file = self.uploads_folder + '/' + filename + '.' + upload_id
        try:
            shutil.rmtree(uploaded_folder)
            os.remove(merged_file)
            res = SerialResumable(self.uploads_folder, 'p11-import_user')
            res._db_remove_completed_for_owner(upload_id)
        except OSError:
            pass


    def test_ZW_resumables_access_control(self):
        filepath = self.resume_file2
        filename = os.path.basename(filepath)
        old_user_token = TEST_TOKENS['VALID']
        upload_id1 = self.start_new_resumable(filepath, chunksize=3, stop_at=2, token=old_user_token)
        new_user_token = gen_test_token_for_user(self.config, 'p11-tommy')
        upload_id2 = self.start_new_resumable(filepath, chunksize=3, stop_at=2, token=new_user_token)
        # ensure user B cannot list user A's resumable
        resp = requests.get(self.resumables, headers={'Authorization': 'Bearer ' + new_user_token})
        data = json.loads(resp.text)
        for r in  data['resumables']:
            self.assertTrue(str(r['id']) != str(upload_id1))
        # ensuere user B cannot delete user A's resumable
        url = '%s/%s?id=%s' % (self.resumables, filename, upload_id1)
        resp = requests.delete(url, headers={'Authorization': 'Bearer ' + new_user_token})
        self.assertEqual(resp.status_code, 400)
        uploaded_folder1 = self.uploads_folder + '/' + upload_id1
        merged_file1 = self.uploads_folder + '/' + filename + '.' + upload_id1
        uploaded_folder2 = self.uploads_folder + '/' + upload_id2
        merged_file2 = self.uploads_folder + '/' + filename + '.' + upload_id2
        try:
            shutil.rmtree(uploaded_folder1)
            os.remove(merged_file2)
            res = SerialResumable(self.uploads_folder, 'p11-import_user')
            res._db_remove_completed_for_owner(upload_id1)
            res = SerialResumable(self.uploads_folder, 'p11-tommy')
            res._db_remove_completed_for_owner(upload_id2)
        except OSError:
            pass


    # resume export
    # following spec described here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests


    def test_ZX_head_for_export_resume_works(self):
        url = self.export + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp1 = requests.head(url, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp1.headers['Accept-Ranges'], 'bytes')
        self.assertEqual(resp1.headers['Content-Length'], '10')
        etag1 = resp1.headers['Etag']
        resp2 = requests.head(url, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        etag2 = resp1.headers['Etag']
        self.assertEqual(etag1, etag2)


    def test_ZY_get_specific_range_for_export(self):
        url = self.export + '/file1'
        # 10-byte file, with index range: 0,1,2,3,4,5,6,7,8,9
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=0-3'} # the first 4 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.headers['Content-Length'], '4')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'some')
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=4-7'} # the next 4 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, ' dat')
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=8-9'} # the last 2 bytes in the file
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'a\n')


    def test_ZZ_get_range_until_end_for_export(self):
        url = self.export + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=5-9'} # 0-indexed, so byte 6 to the end
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'data\n')


    def test_ZZa_get_specific_range_conditional_on_etag(self):
        url = self.export + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp1 = requests.head(url, headers=headers)
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=5-', 'If-Range': resp1.headers['Etag']}
        resp2 = requests.get(url, headers=headers)
        self.assertEqual(resp2.status_code, 200)
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=5-', 'If-Range': '0g04d6de2ecd9d1d1895e2086c8785f1'}
        resp3 = requests.get(url, headers=headers)
        self.assertEqual(resp3.status_code, 400)


    def test_ZZb_get_range_out_of_bounds_returns_correct_error(self):
        url = self.export + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=5-100'}
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 416)


    def test_ZZc_requesting_multiple_ranges_not_supported_error(self):
        url = self.export + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT'],
                   'Range': 'bytes=1-4, 5-10'}
        resp = requests.get(url, headers=headers)
        self.assertEqual(resp.status_code, 405)


    def test_ZZe_filename_rules_with_uploads(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put(self.stream + '/' + url_escape('så_søt(1).txt'),
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        resp = requests.put(self.stream + '/' + url_escape('rød fil (1).txt'),
                            data=lazy_file_reader(self.red),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        resp = requests.put(self.stream + '/' + url_escape('~not allowed'),
                            data=lazy_file_reader(self.red),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)

    # cluster import

    def test_ZZe_cluster_uploads(self):
        token = gen_test_token_for_user(self.config, self.test_user)
        headers = {'Authorization': 'Bearer ' + token,
                   'Expect': '100-Continue'}
        url = self.cluster + '/cluster-upload.csv?group=p11-member-group'
        resp = requests.put(url,
                            data=lazy_file_reader(self.example_csv),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)

    # Cluster export

    def test_ZZf_cluster_export_works(self):
        url = self.export_cluster + '/file1'
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp1 = requests.head(url, headers=headers)
        self.assertEqual(resp1.status_code, 200)
        resp2 = requests.get(url, headers=headers)
        self.assertEqual(resp2.status_code, 200)

    # TODO: store system backend

    def test_ZZg_store_import_and_export(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        resp = requests.put(self.store_import + '/' + url_escape('så_søt(1).txt'),
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp = requests.get(self.store_export + '/' + url_escape('så_søt(1).txt'), headers=headers)
        self.assertEqual(resp.status_code, 200)

    # directories

    def test_ZZZ_put_file_to_dir(self):
        # 1. backend where group logic is enabled
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        # nested, not compliant with group requirements
        file = url_escape('file-should-fail.txt')
        resp = requests.put(
            f'{self.stream}/mydir1/mydir2/{file}',
            data=lazy_file_reader(self.so_sweet),
            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # nested, no group param
        file = url_escape('file-should-be-in-mydir-ååå.txt')
        resp = requests.put(f'{self.stream}/p11-member-group/mydir1/mydir2/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        # not nested, no group info
        file = url_escape('file-should-be-in-default-group-dir.txt')
        resp = requests.put(f'{self.stream}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)

        # not nested, with group param
        file = url_escape('file-should-be-in-default-group-dir2.txt')
        resp = requests.put(f'{self.stream}/{file}?group=p11-member-group',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        # inconsistent group info
        file = url_escape('should-not-make-it.txt')
        resp = requests.put(f'{self.stream}/p11-data-group/mydir1/mydir2/{file}?p11-member-group',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # with legacy Filename header
        file = url_escape('should-make-it.txt')
        legacy_headers = headers.copy()
        legacy_headers['Filename'] = file
        resp = requests.put(f'{self.stream}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=legacy_headers)
        self.assertEqual(resp.status_code, 201)
        # 2. backend without group logic
        file = url_escape('no-group-logic.txt')
        resp = requests.put(f'{self.store_import}/dir1/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)


    def test_ZZZ_patch_resumable_file_to_dir(self):
        self.start_new_resumable(
            self.resume_file1, chunksize=5, endpoint=f'{self.store_import}/dir77',
            uploads_folder=f'{self.store_import_folder}/dir77')


    def test_ZZZ_reserved_resources(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        # 1. hidden files
        file = url_escape('.p11-user.db')
        resp = requests.put(f'{self.store_import}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # 2. resumable data folders
        file = url_escape('myfile.chunk.2')
        test_dir = str(uuid.uuid4())
        test_res_dir = f'{self.store_import_folder}/{test_dir}'
        os.makedirs(test_res_dir)
        with open(f'{self.store_import_folder}/{test_dir}/{file}', 'w') as f:
            f.write('some data')
        resp = requests.put(f'{self.store_import}/{test_dir}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        try:
            shutil.rmtree(f'{self.store_import_folder}/{test_dir}')
        except OSError as e:
            pass
        # 3. merged resumable files
        file = 'file.{0}'.format(str(uuid.uuid4()))
        resp = requests.put(f'{self.store_import}/{test_dir}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # 4. parial upload files
        file = 'file.{0}.part'.format(str(uuid.uuid4()))
        resp = requests.put(f'{self.store_import}/{test_dir}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # 5. export
        file = 'file.{0}.part'.format(str(uuid.uuid4()))
        resp = requests.get(f'{self.store_import}/{test_dir}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)
        # 6. delete
        file = 'file.{0}.part'.format(str(uuid.uuid4()))
        resp = requests.delete(f'{self.store_import}/{test_dir}/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 401)


    def test_ZZZ_listing_dirs(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        resp = requests.get(self.export, headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(self.store_export, headers=headers)
        self.assertEqual(resp.status_code, 200)
        dirs = f'{self.store_import_folder}/topdir/bottomdir'
        try:
            os.makedirs(dirs)
        except OSError:
            pass
        for i in range(101):
            with open(f'{dirs}/file{i}', 'w') as f:
                f.write(f'hi there number {i}')
        resp = requests.get(f'{self.store_export}/topdir', headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(f'{self.store_export}/topdir/bottomdir', headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=0', headers=headers)
        self.assertEqual(resp.status_code, 200)
        data1 = json.loads(resp.text)
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=1', headers=headers)
        self.assertEqual(resp.status_code, 200)
        data2 = json.loads(resp.text)
        self.assertTrue(data2['files'][0] not in data1['files'])
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=0&per_page=103', headers=headers)
        data = json.loads(resp.text)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(data['files']), 101)
        # fail gracefully
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=-1', headers=headers)
        self.assertEqual(resp.status_code, 400)
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=blabla', headers=headers)
        self.assertEqual(resp.status_code, 400)
        resp = requests.get(f'{self.store_export}/topdir/bottomdir?page=1&per_page=1001', headers=headers)
        self.assertEqual(resp.status_code, 400)
        try:
            shutil.rmtree(f'{dirs}')
        except OSError as e:
            pass
        # posix backend
        resp = requests.get(f'{self.export}/data-folder', headers=headers)
        self.assertEqual(resp.status_code, 200)

    def test_ZZZ_listing_import_dir(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        # top level
        # no group included
        resp = requests.get(f'{self.stream}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        # trying a group that the requestor is not a member of
        # will have APIgrant  level access control in addition
        resp = requests.get(f'{self.stream}/p11-bla-group', headers=headers)
        self.assertEqual(resp.status_code, 401)
        # with necessary membership
        resp = requests.get(f'{self.stream}/p11-member-group', headers=headers)
        self.assertEqual(resp.status_code, 200)


    def test_ZZZ_get_file_from_dir(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        dirs = f'{self.store_import_folder}/topdir/bottomdir'
        try:
            os.makedirs(dirs)
        except OSError:
            pass
        with open(f'{dirs}/file1', 'w') as f:
            f.write('hi there')
        with open(f'{dirs}/file2', 'w') as f:
            f.write('how are you?')
        resp = requests.get(f'{self.store_export}/topdir/bottomdir/file1', headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, 'hi there')
        resp = requests.head(f'{self.store_export}/topdir/bottomdir/file1', headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.head(f'{self.store_export}/topdir/bottomdir', headers=headers)
        self.assertEqual(resp.status_code, 403)
        try:
            shutil.rmtree(f'{dirs}')
        except OSError as e:
            pass


    def test_ZZZ_delete(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['EXPORT']}
        dirs = f'{self.store_import_folder}/topdir/bottomdir'
        resp = requests.put(f'{self.store_import}/topdir/bottomdir/file1',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        resp = requests.delete(f'{self.store_export}/topdir/bottomdir/file1', headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue('file1' not in os.listdir(dirs))
        resp = requests.delete(f'{self.store_export}/topdir/bottomdir', headers=headers)
        self.assertEqual(resp.status_code, 403)
        resp = requests.delete(f'{self.store_export}/topdir/bottomdir/nofile', headers=headers)
        self.assertEqual(resp.status_code, 404)
        try:
            shutil.rmtree(f'{dirs}')
        except OSError as e:
            pass


    def test_token_signature_validation(self):
        test_header = 'Bearer ' + TEST_TOKENS['TEST_SIG']
        res = process_access_token(
            test_header,
            self.test_project,
            self.config['token_check_tenant'],
            self.config['token_check_exp'],
            self.config['tenant_claim_name'],
            self.config['jwt_test_secret']
        )
        self.assertTrue(res['status'])


    def test_db_backend(
        self,
        data,
        engine,
        session_func,
        SqlGeneratorCls,
        DbBackendCls,
        verbose
    ):
        def test_select_query(
            uri_query,
            table='test_table',
            engine=engine,
            verbose=verbose
        ):
            out = []
            if verbose:
                print(uri_query)
            q = SqlGeneratorCls(table, uri_query)
            if verbose:
                print(q.select_query)
            with session_func(engine) as session:
                session.execute(q.select_query)
                resp = session.fetchall()
            for row in resp:
                target = row[0]
                if isinstance(target, dict):
                    _in = target
                else:
                    _in = json.loads(target)
                out.append(_in)
            if verbose:
                print(out)
            return out
        def test_update_query(
            uri_query,
            table='test_table',
            engine=engine,
            verbose=verbose,
            data=data
        ):
            q = SqlGeneratorCls(table, uri_query, data=data)
            if verbose:
                print(q.update_query)
            with session_func(engine) as session:
                session.execute(q.update_query)
            with session_func(engine) as session:
                session.execute(f'select * from {table}')
                resp = session.fetchall()
            for row in resp:
                target = row[0]
                if isinstance(target, dict):
                    _in = target
                else:
                    _in = json.loads(target)
                out.append(_in)
            return out
        def test_delete_query(
            uri_query,
            table='test_table',
            engine=engine,
            verbose=verbose
        ):
            q = SqlGeneratorCls(table, uri_query)
            if verbose:
                print(q.delete_query)
            with session_func(engine) as session:
                session.execute(q.delete_query)
            return True
        db = DbBackendCls(engine)
        try:
            db.table_delete('test_table', '')
        except Exception as e:
            pass
        db.table_insert('test_table', data)

        # SELECT
        # simple key selection
        out = test_select_query('select=x')
        for entry in out:
            self.assertTrue('x' in entry.keys())
            self.assertTrue(len(entry.keys()) == 1)
        # more than one simple key
        out = test_select_query('select=x,z')
        for entry in out:
            self.assertTrue('x' in entry.keys() and 'z' in entry.keys())
            self.assertTrue(len(entry.keys()) == 2)
        # nested key
        out = test_select_query('select=a.k1')
        self.assertEqual(out[1]['a']['k1'], None)
        self.assertEqual(out[2]['a']['k1'], {'r1': [1, 2], 'r2': 2})
        # simple array slice
        out = test_select_query('select=x,b[1]')
        self.assertEqual(out[0]['b'], [2])
        self.assertEqual(out[1]['b'], None)
        # nested simple array slice
        out = test_select_query('select=x,a.k2[1]')
        self.assertEqual(out[2]['a']['k2'], [9])
        # selecting a key inside an array slice
        out = test_select_query('select=x,c[1|h]')
        self.assertEqual(out[0]['c'], None)
        self.assertEqual(out[1]['c'], [{'h': 32}])
        # selecting keys inside an array slice
        out = test_select_query('select=x,c[1|h,p]')
        self.assertEqual(out[0]['c'], None)
        self.assertEqual(out[1]['c'], [{'h': 32, 'p': False}])
        # broadcast key selection inside array - single key
        out = test_select_query('select=x,c[*|h]')
        self.assertTrue(len(out[1]['c']) == 3)
        # broadcast key selection inside array - mutliple keys
        out = test_select_query('select=x,c[*|h,p]')
        self.assertTrue(len(out[1]['c']) == 3)
        self.assertEqual(out[1]['c'][0], {'h': 3, 'p': 99})
        # nested array selection
        out = test_select_query('select=a.k1.r1[0]')
        self.assertEqual(out[2]['a']['k1']['r1'], [1])
        # nested key selection inside array
        out = test_select_query('select=a.k3[0|h,z]')

        # WHERE
        # simple key op
        out = test_select_query('select=x&where=x=gt.1000')
        self.assertEqual(out, [{'x': 1900}])
        # multipart simple key ops
        out = test_select_query('select=x&where=x=gt.1000,or:y=eq.11')
        self.assertEqual(out[0], {'x': 1900})
        self.assertEqual(out[1], {'x': None})
        out = test_select_query('select=x&where=x=lt.1000,and:y=eq.11')
        self.assertEqual(out, [])
        # groups
        out = test_select_query('select=x&where=((x=lt.1000,and:y=eq.11),or:x=gt.1000)')
        self.assertEqual(out, [{'x': 1900}])
        # is, not, like, and null
        out = test_select_query('select=x&where=x=not.is.null')
        self.assertTrue(len(out) == 4)
        out = test_select_query('select=d&where=d=not.like.*g3')
        self.assertTrue(len(out) == 2)
        # in
        out = test_select_query('select=d&where=d=in.[string1,string2]')
        self.assertTrue(len(out) == 2)
        self.assertEqual(out, [{'d': 'string1'}, {'d': 'string2'}])
        # nested key ops
        out = test_select_query('select=x&where=a.k1.r1[0]=eq.1')
        self.assertEqual(out, [{'x': 88}])
        out = test_select_query('select=x&where=a.k3[0|h]=eq.0')
        self.assertEqual(out, [{'x': 107}])

        # ORDER
        # Note: postgres and sqlite treat NULLs different in ordering
        # postgres puts them first, sqlite puts them last, so be it
        # simple key
        out = test_select_query('select=x&where=x=not.is.null&order=x.desc')
        x_array = [1900, 107, 88, 10]
        self.assertEqual(list(map(lambda x: x['x'], out)), x_array)
        x_array.reverse()
        out = test_select_query('select=x&where=x=not.is.null&order=x.asc')
        self.assertEqual(list(map(lambda x: x['x'], out)), x_array)
        # array selections
        out = test_select_query('select=x,a&where=a.k1.r1[0]=not.is.null&order=a.k1.r1[0].desc')
        self.assertTrue(out[0]['x'] == 107)
        out = test_select_query('select=x,a&where=a.k3[0|h]=not.is.null&order=a.k3[0|h].desc')
        self.assertTrue(out[0]['x'] == 107)

        # RANGE
        out = test_select_query('select=x&where=x=not.is.null&order=x.desc&range=0.2')
        self.assertEqual(out, [{'x': 1900}, {'x': 107}])
        out = test_select_query('select=x&where=x=not.is.null&order=x.desc&range=1.2')
        self.assertEqual(out, [{'x': 107}, {'x': 88}])

        # UPDATE
        # TODO: select data, check results
        out = test_update_query('set=x&where=x=lt.1000', data={'x': 999})
        out = test_select_query('select=x&where=x=eq.999')
        self.assertEqual(out[0]['x'], 999)
        self.assertTrue(len(out) == 3)

        # DELETE
        out = test_delete_query('where=x=lt.1000')
        self.assertTrue(out is True)
        out = test_select_query('select=x&where=x=lt.1000')
        self.assertEqual(out, [])
        # TODO: ensure date support, with a test


    def test_all_db_backends(self):
        data = [
            {
                'x': 1900,
                'y': 1,
                'z': 5,
                'b':[1, 2, 5, 1],
                'c': None,
                'd': 'string1'
            },
            {
                'y': 11,
                'z': 1,
                'c': [
                    {
                        'h': 3,
                        'p': 99,
                        'w': False
                    },
                    {
                        'h': 32,
                        'p': False,
                        'w': True,
                        'i': {
                            't': [1,2,3]
                        }
                    },
                    {
                        'h': 0
                    }
                ],
                'd': 'string2'
            },
            {
                'a': {
                    'k1': {
                        'r1': [1, 2],
                        'r2': 2
                    },
                    'k2': ['val', 9]
                },
                'z': 0,
                'x': 88,
                'd': 'string3'
            },
            {
                'a': {
                    'k1': {
                        'r1': [33, 200],
                        'r2': 90
                    },
                    'k2': ['val222', 90],
                    'k3': [{'h': 0}]
                },
                'z': 10,
                'x': 107
            },
            {
                'x': 10
            }
        ]
        engine = sqlite_init('/tmp', name='api-test.db', builtin=True)
        try:
            if self.config['backends']['postgres']['dbconfig']:
                pool = postgres_init(self.config['backends']['postgres']['dbconfig'])
        except KeyError as e:
            pool = None
        self.test_db_backend(
            data,
            engine,
            sqlite_session,
            SqliteQueryGenerator,
            SqliteBackend,
            self.verbose
        )
        if pool:
            self.test_db_backend(
                data,
                pool,
                postgres_session,
                PostgresQueryGenerator,
                PostgresBackend,
                self.verbose
            )


    def test_app_backend(self):
        headers = {'Authorization': 'Bearer ' + TEST_TOKENS['VALID']}
        file = url_escape('genetic-data.bam')
        resp = requests.put(f'{self.apps}/ega/files/user1/{file}',
                            data=lazy_file_reader(self.so_sweet),
                            headers=headers)
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(f'{self.apps}/ega/files/user1/{file}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.head(f'{self.apps}/ega/files/user1/{file}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(f'{self.apps}/ega/files/user1/{file}', headers=headers)
        self.assertEqual(resp.status_code, 200)
        self.start_new_resumable(
            self.resume_file1, chunksize=5, endpoint=f'{self.apps}/ega/files/user1',
            uploads_folder=f'{self.apps_import_folder}/ega/files/user1'
        )
        data = [
            {'key1': 7, 'key2': 'bla', 'id': random.randint(0, 1000000)},
            {'key1': 99, 'key3': False, 'id': random.randint(0, 1000000)}
        ]
        headers['Content-Type'] = 'application/json'
        headers['Resource-Identifier'] = 'id'
        resp = requests.put(
            f'{self.apps}/ega/tables/user_data',
            data=json.dumps(data),
            headers=headers
        )
        self.assertEqual(resp.status_code, 201)
        resp = requests.get(
            f'{self.apps}/ega/tables/user_data',
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)
        resp = requests.delete(
            f'{self.apps}/ega/tables/user_data?where=key1=eq.7',
            headers=headers
        )
        self.assertEqual(resp.status_code, 200)


    def test_nacl_crypto(self):

        # https://libnacl.readthedocs.io/en/latest/index.html
        import libnacl
        import libnacl.sealed
        import libnacl.public
        import libnacl.utils

        # server key pair
        server_public_key = base64.b64decode(self.config['test_nacl_public']['public'])
        server_private_key = base64.b64decode(self.config['test_nacl_public']['private'])

        # client
        # Note: for browser clients, e.g.:
        # https://github.com/bcomnes/nacl-blob and https://nacl-blob.netlify.app/
        # https://github.com/tonyg/js-nacl#secret-key-encryption-crypto_stream
        # 1. generate a client secret key and nonce
        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()

        # 2. use it to encrypt payload
        payload = 'hi there'
        encrypted_payload = libnacl.crypto_stream_xor(payload.encode(), nonce, key)

        # 3. use server public key encrypt client secret key, and nonce
        client_sealed_box = libnacl.sealed.SealedBox(libnacl.public.PublicKey(server_public_key))
        cipher_text_key = client_sealed_box.encrypt(key)
        cipher_text_nonce = client_sealed_box.encrypt(nonce)

        # server
        # 1. decrypt the client secret key
        server_sealed_box = libnacl.sealed.SealedBox(libnacl.public.SecretKey(server_private_key))
        decrypted_client_key = server_sealed_box.decrypt(cipher_text_key)
        decrypted_client_nonce = server_sealed_box.decrypt(cipher_text_nonce)
        assert key == decrypted_client_key
        assert nonce == decrypted_client_nonce

        # 2. decrypt the encrypted payload
        decrypted_payload = libnacl.crypto_stream_xor(
            encrypted_payload,
            decrypted_client_nonce,
            decrypted_client_key
        )
        assert decrypted_payload.decode() == payload

        # write an encryptde stream to a file (save a stream)
        chunk_size = 10
        smaller = []
        larger = []
        with open('/tmp/lines', 'w') as f:
            for i in range(20):
                f.write(f'{i} good day sir, hwo are you doing? ')
            f.write('good bye')
        test_file = '/tmp/lines'
        enc_test_file = test_file + '.stream'
        dec_test_file = test_file + '.decr'
        with open(test_file, 'rb') as fplain:
            with open(enc_test_file, 'wb') as fcipher:
                while True:
                    data = fplain.read(chunk_size)
                    if not data:
                        break
                    enc = libnacl.crypto_stream_xor(data, nonce, key)
                    fcipher.write(enc)

        # Simulate getting chunks of different sizes form the network
        # some being too small, and others being too large
        # with respect to the chunk size used to create the encrypted stream.
        # Then recipient (server) needs to accumulate incoming chunks
        # in a buffer, and process the correct sized
        # chunks from that buffer
        _buffer = b''
        small_chunk = chunk_size - 3
        larger_chunk = chunk_size + 1
        line_no = 0
        with open(dec_test_file, 'wb') as fdecrypted:
            with open(enc_test_file, 'rb') as fsmaller:
                while True:
                    line_no += 1
                    if line_no % 2 == 0:
                        size = small_chunk
                    else:
                        size = larger_chunk
                    chunk = fsmaller.read(size)
                    for byte in chunk:
                        _buffer += bytes([byte])
                        if len(_buffer) % chunk_size == 0:
                            decr = libnacl.crypto_stream_xor(_buffer, nonce, key)
                            fdecrypted.write(decr)
                            _buffer = b''
                    if not chunk:
                        break
                if len(_buffer) > 0:
                    decr = libnacl.crypto_stream_xor(_buffer, nonce, key)
                    fdecrypted.write(decr)

        assert md5sum(test_file) == md5sum(dec_test_file)

        # now with requests to the survey backend
        # client setup steps
        resp = requests.get(f'{self.base_url}/survey/crypto/key')
        encoded_public_key = json.loads(resp.text).get('public_key')
        public_key = libnacl.public.PublicKey(base64.b64decode(encoded_public_key))
        sbox = libnacl.sealed.SealedBox(public_key)
        nonce = libnacl.utils.rand_nonce()
        key = libnacl.utils.salsa_key()
        chunk_size = 5
        # save a new encrypted stream to a file, with new nonce, and key
        # this could be generated on the fly while reading the file
        # TODO: test this with a large file
        new_stream = test_file + '.new.stream'
        with open(test_file, 'rb') as fin:
            with open(new_stream, 'wb') as fout:
                while True:
                    data = fin.read(chunk_size)
                    if not data:
                        break
                    enc = libnacl.crypto_stream_xor(data, nonce, key)
                    fout.write(enc)

        # prepare request params
        nacl_nonce = base64.b64encode(sbox.encrypt(nonce))
        nacl_key = base64.b64encode(sbox.encrypt(key))
        nacl_chunksize = chunk_size
        content_type = 'application/octet-stream+nacl'

        # send encrypted data, chunk-wise
        target = '123456/attachments/auto-decrypt1'
        resp = requests.put(
            f'{self.survey}/{target}',
            headers={
                'Content-Type': content_type,
                'Nacl-Nonce': nacl_nonce,
                'Nacl-Key': nacl_key,
                'Nacl-Chunksize': str(nacl_chunksize),
                'Authorization': f"Bearer {TEST_TOKENS['VALID']}"
            },
            data=lazy_file_reader(new_stream)
        )
        self.assertEqual(md5sum(test_file), md5sum(f'{self.uploads_folder_survey}/{target}'))

        # send encrypted data, all in one
        target = '123456/attachments/auto-decrypt2'
        resp = requests.put(
            f'{self.survey}/{target}',
            headers={
                'Content-Type': content_type,
                'Nacl-Nonce': nacl_nonce,
                'Nacl-Key': nacl_key,
                'Nacl-Chunksize': str(nacl_chunksize),
                'Authorization': f"Bearer {TEST_TOKENS['VALID']}"
            },
            data=open(new_stream, 'rb').read()
        )
        self.assertEqual(md5sum(test_file), md5sum(f'{self.uploads_folder_survey}/{target}'))

        # test refuse too large chunk size
        resp = requests.put(
            f'{self.survey}/{target}',
            headers={
                'Content-Type': content_type,
                'Nacl-Nonce': nacl_nonce,
                'Nacl-Key': nacl_key,
                'Nacl-Chunksize': str(500001),
                'Authorization': f"Bearer {TEST_TOKENS['VALID']}"
            },
            data=open(new_stream, 'rb').read()
        )
        self.assertTrue(resp.status_code, 400)

        payload1 = {'x': 10, 'y': 0, 'more': 'all the data yay', 'id': str(uuid.uuid4())}
        payload2 = [
            {'id': str(uuid.uuid4()), 'answers': [i for i in range(1000)]},
            {'id': str(uuid.uuid4()), 'answers': [i for i in range(100)]},
            {'id': str(uuid.uuid4()), 'answers': [i for i in range(10000)]},
        ]
        def encrypt_json(data, nonce, key):
            # return encrypted payload
            # and length of serialised, byte encoded json
            serialised = json.dumps(data).encode()
            enc = libnacl.crypto_stream_xor(serialised, nonce, key)
            return enc, len(serialised)

        target = '444222/submissions'
        for payload in [payload1, payload2]:
            encrypted, chunksize = encrypt_json(payload, nonce, key)
            resp = requests.put(
                f'{self.survey}/{target}',
                headers={
                    'Content-Type': 'application/json+nacl',
                    'Nacl-Nonce': nacl_nonce,
                    'Nacl-Key': nacl_key,
                    'Nacl-Chunksize': str(chunksize),
                    'Authorization': f"Bearer {TEST_TOKENS['VALID']}"
                },
                data=encrypted
            )
            self.assertTrue(resp.status_code, 201)

        # test refuse too large chunk sizes
        resp = requests.put(
            f'{self.survey}/{target}',
            headers={
                'Content-Type': 'application/json+nacl',
                'Nacl-Nonce': nacl_nonce,
                'Nacl-Key': nacl_key,
                'Nacl-Chunksize': str(500001),
                'Authorization': f"Bearer {TEST_TOKENS['VALID']}"
            },
            data=encrypted
        )
        self.assertTrue(resp.status_code, 400)


    def test_maintenance_mode(self):
        maintenance_on = f'{self.maintenance_url}?maintenance=on'
        maintenance_off = f'{self.maintenance_url}?maintenance=off'
        resp = requests.post(maintenance_on)
        resp = requests.put(self.sns_upload)
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f'{self.base_url}/files/resumables')
        self.assertEqual(resp.status_code, 503)
        resp = requests.put(f'{self.base_url}/files/stream/file')
        self.assertEqual(resp.status_code, 503)
        resp = requests.patch(f'{self.base_url}/files/stream/file')
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f'{self.base_url}/files/export/file1')
        self.assertEqual(resp.status_code, 503)
        resp = requests.head(f'{self.base_url}/files/export/file2')
        self.assertEqual(resp.status_code, 503)
        resp = requests.get(f'{self.base_url}/survey')
        self.assertEqual(resp.status_code, 503)
        resp = requests.put(f'{self.base_url}/survey/12345/submissions')
        self.assertEqual(resp.status_code, 503)
        resp = requests.post(maintenance_off)


def main():
    tests = []
    base = [
        # authz
        'test_D_timed_out_token_rejected',
        'test_E_unauthenticated_request_rejected',
        # head
        'test_N_head_on_uploads_fails_when_it_should',
        'test_O_head_on_uploads_succeeds_when_conditions_are_met',
        # tenant logic
        'test_Y_invalid_project_number_rejected',
        'test_Z_token_for_other_project_rejected',
        # upload dirs
        'test_ZA_choosing_file_upload_directories_based_on_tenant_works',
        'test_ZC_setting_ownership_based_on_user_works',
        'test_ZD_cannot_upload_empty_file_to_sns',
        # groups
        'test_ZE_stream_works_with_client_specified_group',
        'test_ZF_stream_does_not_work_with_client_specified_group_wrong_tenant',
        'test_ZG_stream_does_not_work_with_client_specified_group_nonsense_input',
        'test_ZH_stream_does_not_work_with_client_specified_group_not_a_member',
        # resume
        'test_ZM_resume_new_upload_works_is_idempotent',
        'test_ZN_resume_works_with_upload_id_match',
        'test_ZO_resume_works_with_filename_match',
        'test_ZP_resume_do_not_upload_if_md5_mismatch',
        'test_ZR_cancel_resumable',
        'test_ZS_recovering_inconsistent_data_allows_resume_from_previous_chunk',
        'test_ZT_list_all_resumables',
        'test_ZU_sending_uneven_chunks_resume_works',
        'test_ZV_resume_chunk_order_enforced',
        'test_ZW_resumables_access_control',
        # cluster
        'test_ZZe_cluster_uploads',
        'test_ZZf_cluster_export_works',
        # store backend
        'test_ZZg_store_import_and_export',
    ]
    form_data = [
        # form-data
        'test_F_post_file_multi_part_form_data',
        'test_F1_post_file_multi_part_form_data_sns',
        'test_FA_post_multiple_files_multi_part_form_data',
        'test_G_patch_file_multi_part_form_data',
        'test_G1_patch_file_multi_part_form_data_sns',
        'test_GA_patch_multiple_files_multi_part_form_data',
        'test_H_put_file_multi_part_form_data',
        'test_H1_put_file_multi_part_form_data_sns',
        'test_HA_put_multiple_files_multi_part_form_data',
        # sns
        'test_H4XX_when_no_keydir_exists',
        'test_ZB_sns_folder_logic_is_correct',
    ]
    names = [
        'test_ZZe_filename_rules_with_uploads',
    ]
    basic_to_stream = [
        'test_I_put_file_to_streaming_endpoint_no_chunked_encoding_data_binary',
        'test_K_put_stream_file_chunked_transfer_encoding',
    ]
    export = [
        # export
        'test_ZJ_export_file_restrictions_enforced',
        'test_ZK_export_list_dir_works',
        'test_ZL_export_file_works',
        # resume export
        'test_ZX_head_for_export_resume_works',
        'test_ZY_get_specific_range_for_export',
        'test_ZZ_get_range_until_end_for_export',
        'test_ZZa_get_specific_range_conditional_on_etag',
        'test_ZZb_get_range_out_of_bounds_returns_correct_error',
    ]
    pipelines = [
        'test_Za_stream_tar_without_custom_content_type_works',
        'test_Zb_stream_tar_with_custom_content_type_untar_works',
        'test_Zc_stream_tar_gz_with_custom_content_type_untar_works',
        'test_Zg_stream_gz_with_custom_header_decompress_works',
    ]
    gpg_related = [
        'test_Zd_stream_aes_with_custom_content_type_decrypt_works',
        'test_Zd0_stream_aes_with_iv_and_custom_content_type_decrypt_works',
        'test_Zd1_stream_binary_aes_with_iv_and_custom_content_type_decrypt_works',
        'test_Ze_stream_tar_aes_with_custom_content_type_decrypt_untar_works',
        'test_Ze0_stream_tar_aes_with_iv_and_custom_content_type_decrypt_untar_works',
        'test_Zf_stream_tar_aes_with_custom_content_type_decrypt_untar_works',
        'test_Zf0_stream_tar_aes_with_iv_and_custom_content_type_decrypt_untar_works',
        'test_Zh_stream_gz_aes_with_custom_header_decompress_works',
        'test_Zh0_stream_gz_with_iv_and_custom_header_decompress_works',
    ]
    dirs = [
        'test_ZZZ_put_file_to_dir',
        'test_ZZZ_patch_resumable_file_to_dir',
        'test_ZZZ_get_file_from_dir',
    ]
    listing = [
        'test_ZZZ_listing_dirs',
        'test_ZZZ_listing_import_dir',
    ]
    delete = [
        'test_ZZZ_delete',
    ]
    reserved = [
        'test_ZZZ_reserved_resources',
    ]
    sig = [
        'test_token_signature_validation',
    ]
    ns = [
        'test_XXX_nettskjema_backend',
    ]
    load = [
        'test_XXX_load'
    ]
    db = [
        'test_all_db_backends',
    ]
    apps = [
        'test_app_backend',
    ]
    crypt = [
        'test_nacl_crypto'
    ]
    maintenance = [
        'test_maintenance_mode',
    ]
    if len(sys.argv) == 2:
        print('usage:')
        print('python3 tsdfileapi/test_file_api.py config.yaml ARGS')
        print('ARGS: all, base, names, pipelines, export, basic-stream, gpg, dirs, listing')
        sys.exit(0)
    if 'base' in sys.argv:
        tests.extend(base)
    if 'form_data' in sys.argv:
        tests.extend(form_data)
    if 'names' in sys.argv:
        tests.extend(names)
    if 'pipelines' in sys.argv:
        tests.extend(pipelines)
    if 'gpg' in sys.argv:
        tests.extend(gpg_related)
    if 'dirs' in sys.argv:
        tests.extend(dirs)
    if 'export' in sys.argv:
        tests.extend(export)
    if 'basic-stream' in sys.argv:
        tests.extend(basic_to_stream)
    if 'reserved' in sys.argv:
        tests.extend(reserved)
    if 'listing' in sys.argv:
        tests.extend(listing)
    if 'delete' in sys.argv:
        tests.extend(delete)
    if 'sig' in sys.argv:
        tests.extend(sig)
    if 'ns' in sys.argv:
        tests.extend(ns)
    if 'load' in sys.argv:
        tests.extend(load)
    if 'db' in sys.argv:
        tests.extend(db)
    if 'apps' in sys.argv:
        tests.extend(apps)
    if 'crypt' in sys.argv:
        tests.extend(crypt)
    if 'maintenance' in sys.argv:
        tests.extend(maintenance)
    if 'all' in sys.argv:
        tests.extend(base)
        tests.extend(names)
        tests.extend(pipelines)
        tests.extend(gpg_related)
        tests.extend(dirs)
        tests.extend(export)
        tests.extend(basic_to_stream)
        tests.extend(reserved)
        tests.extend(listing)
        tests.extend(delete)
        tests.extend(sig)
        tests.extend(ns)
        tests.extend(apps)
        tests.extend(db)
        tests.extend(crypt)
        tests.extend(form_data)
    tests.sort()
    suite = unittest.TestSuite()
    for test in tests:
        suite.addTest(TestFileApi(test))
    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == '__main__':
    main()
