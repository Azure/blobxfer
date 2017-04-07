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
import blobxfer.models.azure
import blobxfer.models.download
import blobxfer.models.options
import blobxfer.operations.azure
import blobxfer.operations.crypto
import blobxfer.util


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
    if blobxfer.util.is_not_empty(storage_account):
        # add credentials
        try:
            key = cli_options['access_key']
            if blobxfer.util.is_none_or_empty(key):
                raise KeyError()
        except KeyError:
            try:
                key = cli_options['sas']
                if blobxfer.util.is_none_or_empty(key):
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
                    'chunk_size_bytes': cli_options['chunk_size_bytes'],
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
            if blobxfer.util.is_none_or_empty(sync_copy_dest_storage_account):
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
                    'chunk_size_bytes': cli_options['chunk_size_bytes'],
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
                if blobxfer.util.is_none_or_empty(destkey):
                    raise KeyError()
            except KeyError:
                try:
                    destkey = cli_options['sync_copy_dest_sas']
                    if blobxfer.util.is_none_or_empty(destkey):
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
        config['azure_storage'] = blobxfer.util.merge_dict(
            config['azure_storage'], cli_options['azure_storage'])
    # merge general options
    if 'options' not in config:
        config['options'] = {}
    config['options']['crypto_processes'] = cli_options['crypto_processes']
    config['options']['log_file'] = cli_options['log_file']
    config['options']['md5_processes'] = cli_options['md5_processes']
    config['options']['progress_bar'] = cli_options['progress_bar']
    config['options']['resume_file'] = cli_options['resume_file']
    config['options']['timeout_sec'] = cli_options['timeout']
    config['options']['transfer_threads'] = cli_options['transfer_threads']
    config['options']['verbose'] = cli_options['verbose']


def create_azure_storage_credentials(config):
    # type: (dict) -> blobxfer.operations.azure.StorageCredentials
    """Create an Azure StorageCredentials object from configuration
    :param dict config: config dict
    :rtype: blobxfer.operations.azure.StorageCredentials
    :return: credentials object
    """
    creds = blobxfer.operations.azure.StorageCredentials()
    endpoint = config['azure_storage']['endpoint']
    for name in config['azure_storage']['accounts']:
        key = config['azure_storage']['accounts'][name]
        creds.add_storage_account(name, key, endpoint)
    return creds


def create_general_options(config):
    # type: (dict) -> blobxfer.models.options.General
    """Create a General Options object from configuration
    :param dict config: config dict
    :rtype: blobxfer.models.options.General
    :return: general options object
    """
    return blobxfer.models.options.General(
        concurrency=blobxfer.models.options.Concurrency(
            crypto_processes=config['options']['crypto_processes'],
            md5_processes=config['options']['md5_processes'],
            transfer_threads=config['options']['transfer_threads'],
        ),
        log_file=config['options']['log_file'],
        progress_bar=config['options']['progress_bar'],
        resume_file=config['options']['resume_file'],
        timeout_sec=config['options']['timeout_sec'],
        verbose=config['options']['verbose'],
    )


def create_download_specifications(config):
    # type: (dict) -> List[blobxfer.models.download.Specification]
    """Create a list of Download Specification objects from configuration
    :param dict config: config dict
    :rtype: list
    :return: list of Download Specification objects
    """
    specs = []
    for conf in config['download']:
        # create download options
        confmode = conf['options']['mode'].lower()
        if confmode == 'auto':
            mode = blobxfer.models.azure.StorageModes.Auto
        elif confmode == 'append':
            mode = blobxfer.models.azure.StorageModes.Append
        elif confmode == 'block':
            mode = blobxfer.models.azure.StorageModes.Block
        elif confmode == 'file':
            mode = blobxfer.models.azure.StorageModes.File
        elif confmode == 'page':
            mode = blobxfer.models.azure.StorageModes.Page
        else:
            raise ValueError('unknown mode: {}'.format(confmode))
        # load RSA private key PEM file if specified
        rpk = conf['options']['rsa_private_key']
        if blobxfer.util.is_not_empty(rpk):
            rpkp = conf['options']['rsa_private_key_passphrase']
            rpk = blobxfer.operations.crypto.load_rsa_private_key_file(
                rpk, rpkp)
        else:
            rpk = None
        ds = blobxfer.models.download.Specification(
            download_options=blobxfer.models.options.Download(
                check_file_md5=conf['options']['check_file_md5'],
                chunk_size_bytes=conf['options']['chunk_size_bytes'],
                delete_extraneous_destination=conf[
                    'options']['delete_extraneous_destination'],
                mode=mode,
                overwrite=conf['options']['overwrite'],
                recursive=conf['options']['recursive'],
                restore_file_attributes=conf[
                    'options']['restore_file_attributes'],
                rsa_private_key=rpk,
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=conf['options']['skip_on']['filesize_match'],
                lmt_ge=conf['options']['skip_on']['lmt_ge'],
                md5_match=conf['options']['skip_on']['md5_match'],
            ),
            local_destination_path=blobxfer.models.download.
            LocalDestinationPath(
                conf['destination']
            )
        )
        # create remote source paths
        for src in conf['source']:
            if len(src) != 1:
                raise RuntimeError(
                    'invalid number of source pairs specified per entry')
            sa = next(iter(src))
            asp = blobxfer.operations.azure.SourcePath()
            asp.add_path_with_storage_account(src[sa], sa)
            if blobxfer.util.is_not_empty(conf['include']):
                asp.add_includes(conf['include'])
            if blobxfer.util.is_not_empty(conf['exclude']):
                asp.add_excludes(conf['exclude'])
            ds.add_azure_source_path(asp)
        specs.append(ds)
    return specs
