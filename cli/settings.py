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
import blobxfer.models.synccopy
import blobxfer.models.upload
import blobxfer.operations.azure
import blobxfer.operations.crypto
import blobxfer.util


# enums
class TransferAction(enum.Enum):
    Download = 1,
    Upload = 2,
    Synccopy = 3,


def add_cli_options(cli_options, action):
    # type: (dict, str) -> None
    """Adds CLI options to the configuration object
    :param dict cli_options: CLI options dict
    :param TransferAction action: action
    """
    cli_options['_action'] = action.name.lower()
    storage_account = cli_options['storage_account']
    if blobxfer.util.is_not_empty(storage_account):
        try:
            local_resource = cli_options['local_resource']
            if blobxfer.util.is_none_or_empty(local_resource):
                raise KeyError()
        except KeyError:
            raise ValueError('--local-path must be specified')
        try:
            remote_path = cli_options['remote_path']
            if blobxfer.util.is_none_or_empty(remote_path):
                raise KeyError()
        except KeyError:
            raise ValueError('--remote-path must be specified')
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
                    'one_shot_bytes': cli_options['one_shot_bytes'],
                    'overwrite': cli_options['overwrite'],
                    'recursive': cli_options['recursive'],
                    'rename': cli_options['rename'],
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
                    'store_file_properties': {
                        'attributes': cli_options['file_attributes'],
                        'md5': cli_options['file_md5'],
                    },
                    'strip_components': cli_options['strip_components'],
                    'vectored_io': {
                        'stripe_chunk_size_bytes': cli_options[
                            'stripe_chunk_size_bytes'],
                        'distribution_mode': cli_options['distribution_mode'],
                    },
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
                    'rename': cli_options['rename'],
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
            try:
                sync_copy_dest_storage_account = \
                    cli_options['sync_copy_dest_storage_account']
                if blobxfer.util.is_none_or_empty(
                        sync_copy_dest_storage_account):
                    raise KeyError()
            except KeyError:
                raise ValueError(
                    '--sync-copy-dest-storage-account must be specified')
            try:
                sync_copy_dest_remote_path = \
                    cli_options['sync_copy_dest_remote_path']
                if blobxfer.util.is_none_or_empty(sync_copy_dest_remote_path):
                    raise KeyError()
            except KeyError:
                raise ValueError(
                    '--sync-copy-dest-remote-path must be specified')
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
            action != TransferAction.Synccopy.name.lower()):
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
    config['options']['log_file'] = cli_options['log_file']
    config['options']['progress_bar'] = cli_options['progress_bar']
    config['options']['resume_file'] = cli_options['resume_file']
    config['options']['timeout_sec'] = cli_options['timeout']
    config['options']['verbose'] = cli_options['verbose']
    # merge concurrency options
    if 'concurrency' not in config['options']:
        config['options']['concurrency'] = {}
    config['options']['concurrency']['crypto_processes'] = \
        cli_options['crypto_processes']
    config['options']['concurrency']['disk_threads'] = \
        cli_options['disk_threads']
    config['options']['concurrency']['md5_processes'] = \
        cli_options['md5_processes']
    config['options']['concurrency']['transfer_threads'] = \
        cli_options['transfer_threads']


def create_azure_storage_credentials(config, general_options):
    # type: (dict, blobxfer.models.options.General) ->
    #        blobxfer.operations.azure.StorageCredentials
    """Create an Azure StorageCredentials object from configuration
    :param dict config: config dict
    :param blobxfer.models.options.General: general options
    :rtype: blobxfer.operations.azure.StorageCredentials
    :return: credentials object
    """
    creds = blobxfer.operations.azure.StorageCredentials(general_options)
    endpoint = config['azure_storage']['endpoint']
    for name in config['azure_storage']['accounts']:
        key = config['azure_storage']['accounts'][name]
        creds.add_storage_account(name, key, endpoint)
    return creds


def create_general_options(config, action):
    # type: (dict, TransferAction) -> blobxfer.models.options.General
    """Create a General Options object from configuration
    :param dict config: config dict
    :param TransferAction action: transfer action
    :rtype: blobxfer.models.options.General
    :return: general options object
    """
    conc = config['options'].get('concurrency', {})
    return blobxfer.models.options.General(
        concurrency=blobxfer.models.options.Concurrency(
            crypto_processes=conc.get('crypto_processes', 0),
            disk_threads=conc.get('disk_threads', 0),
            md5_processes=conc.get('md5_processes', 0),
            transfer_threads=conc.get('transfer_threads', 0),
            action=action.value[0],
        ),
        log_file=config['options'].get('log_file', None),
        progress_bar=config['options'].get('progress_bar', True),
        resume_file=config['options'].get('resume_file', None),
        timeout_sec=config['options'].get('timeout_sec', None),
        verbose=config['options'].get('verbose', False),
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
        confmode = conf['options'].get('mode', 'auto').lower()
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
        rpk = conf['options'].get('rsa_private_key', None)
        if blobxfer.util.is_not_empty(rpk):
            rpkp = conf['options'].get('rsa_private_key_passphrase', None)
            rpk = blobxfer.operations.crypto.load_rsa_private_key_file(
                rpk, rpkp)
        else:
            rpk = None
        # create specification
        sod = conf['options'].get('skip_on', {})
        ds = blobxfer.models.download.Specification(
            download_options=blobxfer.models.options.Download(
                check_file_md5=conf['options'].get('check_file_md5', False),
                chunk_size_bytes=conf['options'].get('chunk_size_bytes', 0),
                delete_extraneous_destination=conf['options'].get(
                    'delete_extraneous_destination', False),
                mode=mode,
                overwrite=conf['options'].get('overwrite', True),
                recursive=conf['options'].get('recursive', True),
                rename=conf['options'].get('rename', False),
                restore_file_attributes=conf[
                    'options'].get('restore_file_attributes', False),
                rsa_private_key=rpk,
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=sod.get('filesize_match', False),
                lmt_ge=sod.get('lmt_ge', False),
                md5_match=sod.get('md5_match', False),
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
            incl = conf.get('include', None)
            if blobxfer.util.is_not_empty(incl):
                asp.add_includes(incl)
            excl = conf.get('exclude', None)
            if blobxfer.util.is_not_empty(excl):
                asp.add_excludes(excl)
            ds.add_azure_source_path(asp)
        # append spec to list
        specs.append(ds)
    return specs


def create_synccopy_specifications(config):
    # type: (dict) -> List[blobxfer.models.synccopy.Specification]
    """Create a list of SyncCopy Specification objects from configuration
    :param dict config: config dict
    :rtype: list
    :return: list of SyncCopy Specification objects
    """
    specs = []
    for conf in config['synccopy']:
        # create download options
        confmode = conf['options'].get('mode', 'auto').lower()
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
        # create specification
        sod = conf['options'].get('skip_on', {})
        scs = blobxfer.models.synccopy.Specification(
            synccopy_options=blobxfer.models.options.SyncCopy(
                delete_extraneous_destination=conf['options'].get(
                    'delete_extraneous_destination', False),
                mode=mode,
                overwrite=conf['options'].get('overwrite', True),
                recursive=conf['options'].get('recursive', True),
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=sod.get('filesize_match', False),
                lmt_ge=sod.get('lmt_ge', False),
                md5_match=sod.get('md5_match', False),
            ),
        )
        # create remote source paths
        for src in conf['source']:
            sa = next(iter(src))
            asp = blobxfer.operations.azure.SourcePath()
            asp.add_path_with_storage_account(src[sa], sa)
            incl = conf.get('include', None)
            if blobxfer.util.is_not_empty(incl):
                asp.add_includes(incl)
            excl = conf.get('exclude', None)
            if blobxfer.util.is_not_empty(excl):
                asp.add_excludes(excl)
            scs.add_azure_source_path(asp)
        # create remote destination paths
        for dst in conf['destination']:
            if len(dst) != 1:
                raise RuntimeError(
                    'invalid number of destination pairs specified per entry')
            sa = next(iter(dst))
            adp = blobxfer.operations.azure.DestinationPath()
            adp.add_path_with_storage_account(dst[sa], sa)
            scs.add_azure_destination_path(adp)
        # append spec to list
        specs.append(scs)
    return specs


def create_upload_specifications(config):
    # type: (dict) -> List[blobxfer.models.upload.Specification]
    """Create a list of Upload Specification objects from configuration
    :param dict config: config dict
    :rtype: list
    :return: list of Upload Specification objects
    """
    specs = []
    for conf in config['upload']:
        # create upload options
        confmode = conf['options'].get('mode', 'auto').lower()
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
        # load RSA public key PEM if specified
        rpk = conf['options'].get('rsa_public_key', None)
        if blobxfer.util.is_not_empty(rpk):
            rpk = blobxfer.operations.crypto.load_rsa_public_key_file(rpk)
        if rpk is None:
            # load RSA private key PEM file if specified
            rpk = conf['options'].get('rsa_private_key', None)
            if blobxfer.util.is_not_empty(rpk):
                rpkp = conf['options'].get('rsa_private_key_passphrase', None)
                rpk = blobxfer.operations.crypto.load_rsa_private_key_file(
                    rpk, rpkp)
                rpk = rpk.public_key()
            else:
                rpk = None
        # create local source paths
        lsp = blobxfer.models.upload.LocalSourcePath()
        lsp.add_paths(conf['source'])
        incl = conf.get('include', None)
        if blobxfer.util.is_not_empty(incl):
            lsp.add_includes(incl)
        excl = conf.get('exclude', None)
        if blobxfer.util.is_not_empty(excl):
            lsp.add_excludes(excl)
        # create specification
        sfp = conf['options'].get('store_file_properties', {})
        vio = conf['options'].get('vectored_io', {})
        sod = conf['options'].get('skip_on', {})
        us = blobxfer.models.upload.Specification(
            upload_options=blobxfer.models.options.Upload(
                chunk_size_bytes=conf['options'].get('chunk_size_bytes', 0),
                delete_extraneous_destination=conf['options'].get(
                    'delete_extraneous_destination', False),
                mode=mode,
                one_shot_bytes=conf['options'].get('one_shot_bytes', 0),
                overwrite=conf['options'].get('overwrite', True),
                recursive=conf['options'].get('recursive', True),
                rename=conf['options'].get('rename', False),
                rsa_public_key=rpk,
                store_file_properties=blobxfer.models.options.FileProperties(
                    attributes=sfp.get('attributes', False),
                    md5=sfp.get('md5', False),
                ),
                strip_components=conf['options'].get('strip_components', 1),
                vectored_io=blobxfer.models.options.VectoredIo(
                    stripe_chunk_size_bytes=vio.get(
                        'stripe_chunk_size_bytes', 1073741824),
                    distribution_mode=blobxfer.
                    models.upload.VectoredIoDistributionMode(
                        vio.get('distribution_mode', 'disabled').lower()),
                ),
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=sod.get('filesize_match', False),
                lmt_ge=sod.get('lmt_ge', False),
                md5_match=sod.get('md5_match', False),
            ),
            local_source_path=lsp,
        )
        # create remote destination paths
        for dst in conf['destination']:
            if len(dst) != 1:
                raise RuntimeError(
                    'invalid number of destination pairs specified per entry')
            sa = next(iter(dst))
            adp = blobxfer.operations.azure.DestinationPath()
            adp.add_path_with_storage_account(dst[sa], sa)
            us.add_azure_destination_path(adp)
        # append spec to list
        specs.append(us)
    return specs
