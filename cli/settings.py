# Copyright (c) Microsoft Corporation
#
# All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# compat imports
from __future__ import (
    absolute_import, division, print_function, unicode_literals
)
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip)
# stdlib imports
import enum
# non-stdlib imports
# local imports
from blobxfer.util import is_none_or_empty, is_not_empty, merge_dict


# enums
class TransferAction(enum.Enum):
    Download = 1,
    Upload = 2,
    Synccopy = 3,


def add_cli_options(
        cli_options, action, local_resource=None, storage_account=None,
        remote_path=None, sync_copy_dest_storage_account=None,
        sync_copy_dest_remote_path=None):
    # type: (dict, str, str, str, str, str, str) -> None
    """Adds CLI options to the configuration object
    :param dict cli_options: CLI options dict
    :param TransferAction action: action
    :param str local_resource: local resource
    :param str storage_account: storage account
    :param str remote_path: remote path
    :param str sync_copy_dest_storage_account: synccopy dest sa
    :param str sync_copy_dest_remote_path: synccopy dest rp
    """
    cli_options['_action'] = action.name.lower()
    if is_not_empty(storage_account):
        # add credentials
        try:
            key = cli_options['access_key']
            if is_none_or_empty(key):
                raise KeyError()
        except KeyError:
            try:
                key = cli_options['sas']
                if is_none_or_empty(key):
                    raise KeyError()
            except KeyError:
                raise RuntimeError('access key or sas must be provided')
        azstorage = {
            'endpoint': cli_options['endpoint'],
            'accounts': {
                storage_account: key
            }
        }
        del key
        # construct "argument" from cli options
        sa_rp = {storage_account: remote_path}
        if action == TransferAction.Upload:
            arg = {
                'source': [local_resource],
                'destination': [sa_rp],
                'include': cli_options['include'],
                'exclude': cli_options['exclude'],
                'options': {
                    'chunk_size_bytes': cli_options['chunk_size_bytes'],
                    'delete_extraneous_destination': cli_options['delete'],
                    'mode': cli_options['mode'],
                    'overwrite': cli_options['overwrite'],
                    'recursive': cli_options['recursive'],
                    'rsa_private_key': cli_options['rsa_private_key'],
                    'rsa_private_key_passphrase': cli_options[
                        'rsa_private_key_passphrase'],
                    'rsa_public_key': cli_options['rsa_public_key'],
                    'skip_on': {
                        'filesize_match': cli_options[
                            'skip_on_filesize_match'],
                        'lmt_ge': cli_options['skip_on_lmt_ge'],
                        'md5_match': cli_options['skip_on_md5_match'],
                    },
                    'store_file_attributes': cli_options['file_attributes'],
                    'store_file_md5': cli_options['file_md5'],
                    'strip_components': cli_options['strip_components'],
                },
            }
        elif action == TransferAction.Download:
            arg = {
                'source': [sa_rp],
                'destination': local_resource,
                'include': cli_options['include'],
                'exclude': cli_options['exclude'],
                'options': {
                    'check_file_md5': cli_options['file_md5'],
                    'delete_extraneous_destination': cli_options['delete'],
                    'mode': cli_options['mode'],
                    'overwrite': cli_options['overwrite'],
                    'recursive': cli_options['recursive'],
                    'rsa_private_key': cli_options['rsa_private_key'],
                    'rsa_private_key_passphrase': cli_options[
                        'rsa_private_key_passphrase'],
                    'restore_file_attributes': cli_options['file_attributes'],
                    'skip_on': {
                        'filesize_match': cli_options[
                            'skip_on_filesize_match'],
                        'lmt_ge': cli_options['skip_on_lmt_ge'],
                        'md5_match': cli_options['skip_on_md5_match'],
                    },
                },
            }
        elif action == TransferAction.Synccopy:
            if is_none_or_empty(sync_copy_dest_storage_account):
                raise RuntimeError(
                    'must specify a destination storage account')
            arg = {
                'source': sa_rp,
                'destination': [
                    {
                        sync_copy_dest_storage_account:
                        sync_copy_dest_remote_path
                    }
                ],
                'include': cli_options['include'],
                'exclude': cli_options['exclude'],
                'options': {
                    'mode': cli_options['mode'],
                    'overwrite': cli_options['overwrite'],
                    'skip_on': {
                        'filesize_match': cli_options[
                            'skip_on_filesize_match'],
                        'lmt_ge': cli_options['skip_on_lmt_ge'],
                        'md5_match': cli_options['skip_on_md5_match'],
                    },
                },
            }
            try:
                destkey = cli_options['sync_copy_dest_access_key']
                if is_none_or_empty(destkey):
                    raise KeyError()
            except KeyError:
                try:
                    destkey = cli_options['sync_copy_dest_sas']
                    if is_none_or_empty(destkey):
                        raise KeyError()
                except KeyError:
                    raise RuntimeError(
                        'destination access key or sas must be provided')
            azstorage['accounts'][
                cli_options['sync_copy_dest_storage_account']] = destkey
            del destkey
        cli_options[action.name.lower()] = arg
        cli_options['azure_storage'] = azstorage


def merge_settings(config, cli_options):
    # type: (dict, dict) -> None
    """Merge CLI options into main config
    :param dict config: config dict
    :param dict cli_options: cli options
    """
    action = cli_options['_action']
    if (action != TransferAction.Upload.name.lower() and
            action != TransferAction.Download.name.lower() and
            action == TransferAction.Synccopy.name.lower()):
        raise ValueError('invalid action: {}'.format(action))
    # create action options
    if action not in config:
        config[action] = []
    # merge any argument options
    if action in cli_options:
        config[action].append(cli_options[action])
    # merge credentials
    if 'azure_storage' in cli_options:
        if 'azure_storage' not in config:
            config['azure_storage'] = {}
        config['azure_storage'] = merge_dict(
            config['azure_storage'], cli_options['azure_storage'])
    # merge general options
    if 'options' not in config:
        config['options'] = {}
    try:
        config['options']['verbose'] = cli_options['verbose']
    except KeyError:
        pass
    try:
        config['options']['timeout_sec'] = cli_options['timeout']
    except KeyError:
        pass
