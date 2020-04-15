# -*- coding: utf-8 -*-

import os
import re
import logging
import hashlib
import subprocess
import shlex
import re
import shutil


_VALID_FORMID = re.compile(r'^[0-9]+$')
_IS_REALISTIC_PGP_KEY_FINGERPRINT = re.compile(r'^[0-9A-Z]{16}$')
_IS_VALID_UUID = re.compile(r'([a-f\d0-9-]{32,36})')


def call_request_hook(path, params, as_sudo=True):
    if as_sudo:
        cmd = ['sudo']
    else:
        cmd = []
    cmd.append(shlex.quote(path))
    cmd.extend(params)
    subprocess.call(cmd)


class IllegalFilenameException(Exception):
    message = 'Filename not allowed'


def tenant_from_url(url):
    if 'v1' in url:
        idx = 2
    else:
        idx = 1
    return url.split('/')[idx]


def check_filename(filename, disallowed_start_chars=[]):
    try:
        start_char = filename[0]
        if disallowed_start_chars:
            if start_char in disallowed_start_chars:
                logging.error('Filename has illegal start character: {0}'.format(start_char))
                raise Exception
    except Exception:
        raise IllegalFilenameException
    return filename


def create_cluster_dir_if_not_exists(path, tenant, tenant_string_pattern):
    base = os.path.abspath(os.path.join(path, os.pardir))
    target = path.replace(tenant_string_pattern, tenant)
    if os.path.lexists(base):
        if not os.path.lexists(target):
            os.makedirs(target)
        return target
    else:
        raise Exception('{0} does not have a cluster disk space'.format(tenant))


def sns_dir(base_pattern, tenant, uri, tenant_string_pattern, test=False):
    """
    Construct a path for sns uploads.

    Paramaters
    ----------
    config: dict
    tenant: str
    uri: request uri
    test: bool

    Returns
    -------
    path

    """
    try:
        uri_parts = uri.split('/')
        formid = uri_parts[-1]
        keyid = uri_parts[-2]
        assert _VALID_FORMID.match(formid), f'invalid form ID: {formid}'
        assert _IS_REALISTIC_PGP_KEY_FINGERPRINT.match(keyid), f'invalid PGP fingerprint: {keyid}'
        folder = base_pattern.replace(tenant_string_pattern, tenant).replace('KEYID', keyid).replace('FORMID', formid)
        _path = os.path.normpath(folder)
        if test:
            return _path
        if not os.path.lexists(_path):
            logging.info('Creating %s', _path)
            os.makedirs(_path)
            subprocess.call(['chmod', '2770', _path])
        return _path
    except (Exception, AssertionError) as e:
        logging.error(e)
        raise e


def md5sum(filename, blocksize=65536):
    _hash = hashlib.md5()
    with open(filename, "rb") as f:
        for block in iter(lambda: f.read(blocksize), b""):
            _hash.update(block)
    return _hash.hexdigest()


def move_data_to_folder(path, dest):
    """
    Move file/dir at path into and folder at dest.

    Parameters
    ----------
    path: str, uploaded file or folder
    dest: name of the destination folder

    Returns
    -------
    boolean

    """
    try:
        if not dest:
            return path
        filename = os.path.basename(path)
        base_dir = path.replace(f'/{filename}', '')
        new_path = os.path.normpath(dest + '/' + filename)
        if os.path.isdir(path):
            if os.path.lexists(new_path):
                # idempotency
                shutil.rmtree(new_path)
            shutil.move(path, new_path)
        else:
            os.rename(path, new_path)
        return new_path
    except Exception as e:
        logging.error(e)
        logging.error('could not move file: %s', path)
        return False
