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


# global defines
_SUPPORTED_YAML_CONFIG_VERSIONS = frozenset((1,))


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
    storage_account = cli_options.get('storage_account')
    azstorage = {
        'endpoint': cli_options.get('endpoint')
    }
    if blobxfer.util.is_not_empty(storage_account):
        azstorage['accounts'] = {
            storage_account: (
                cli_options.get('access_key') or cli_options.get('sas')
            )
        }
    sa_rp = {
        storage_account: cli_options.get('remote_path')
    }
    local_resource = cli_options.get('local_resource')
    # construct "argument" from cli options
    if action == TransferAction.Download:
        arg = {
            'source': [sa_rp] if sa_rp[storage_account] is not None else None,
            'destination': local_resource if local_resource is not None else
            None,
            'include': cli_options.get('include'),
            'exclude': cli_options.get('exclude'),
            'options': {
                'check_file_md5': cli_options.get('file_md5'),
                'chunk_size_bytes': cli_options.get('chunk_size_bytes'),
                'delete_extraneous_destination': cli_options.get('delete'),
                'mode': cli_options.get('mode'),
                'overwrite': cli_options.get('overwrite'),
                'recursive': cli_options.get('recursive'),
                'rename': cli_options.get('rename'),
                'rsa_private_key': cli_options.get('rsa_private_key'),
                'rsa_private_key_passphrase': cli_options.get(
                    'rsa_private_key_passphrase'),
                'restore_file_attributes': cli_options.get(
                    'file_attributes'),
                'strip_components': cli_options.get('strip_components'),
                'skip_on': {
                    'filesize_match': cli_options.get(
                        'skip_on_filesize_match'),
                    'lmt_ge': cli_options.get('skip_on_lmt_ge'),
                    'md5_match': cli_options.get('skip_on_md5_match'),
                },
            },
        }
    elif action == TransferAction.Synccopy:
        sync_copy_dest_storage_account = cli_options.get(
            'sync_copy_dest_storage_account')
        sync_copy_dest_remote_path = cli_options.get(
            'sync_copy_dest_remote_path')
        if (sync_copy_dest_storage_account is not None and
                sync_copy_dest_remote_path is not None):
            sync_copy_dest = [
                {
                    sync_copy_dest_storage_account:
                    sync_copy_dest_remote_path
                }
            ]
            azstorage['accounts'][sync_copy_dest_storage_account] = (
                cli_options.get('sync_copy_dest_access_key') or
                cli_options.get('sync_copy_dest_sas')
            )
        else:
            sync_copy_dest = None
        arg = {
            'source': [sa_rp] if sa_rp[storage_account] is not None else None,
            'destination': sync_copy_dest,
            'include': cli_options.get('include'),
            'exclude': cli_options.get('exclude'),
            'options': {
                'access_tier': cli_options.get('access_tier'),
                'chunk_size_bytes': cli_options.get('chunk_size_bytes'),
                'dest_mode': cli_options.get('sync_copy_dest_mode'),
                'mode': cli_options.get('mode'),
                'overwrite': cli_options.get('overwrite'),
                'rename': cli_options.get('rename'),
                'skip_on': {
                    'filesize_match': cli_options.get(
                        'skip_on_filesize_match'),
                    'lmt_ge': cli_options.get('skip_on_lmt_ge'),
                    'md5_match': cli_options.get('skip_on_md5_match'),
                },
            },
        }
    elif action == TransferAction.Upload:
        arg = {
            'source': [local_resource] if local_resource is not None else None,
            'destination': [sa_rp] if sa_rp[storage_account] is not None else
            None,
            'include': cli_options.get('include'),
            'exclude': cli_options.get('exclude'),
            'options': {
                'access_tier': cli_options.get('access_tier'),
                'chunk_size_bytes': cli_options.get('chunk_size_bytes'),
                'delete_extraneous_destination': cli_options.get('delete'),
                'mode': cli_options.get('mode'),
                'one_shot_bytes': cli_options.get('one_shot_bytes'),
                'overwrite': cli_options.get('overwrite'),
                'recursive': cli_options.get('recursive'),
                'rename': cli_options.get('rename'),
                'rsa_private_key': cli_options.get('rsa_private_key'),
                'rsa_private_key_passphrase': cli_options.get(
                    'rsa_private_key_passphrase'),
                'rsa_public_key': cli_options.get('rsa_public_key'),
                'skip_on': {
                    'filesize_match': cli_options.get(
                        'skip_on_filesize_match'),
                    'lmt_ge': cli_options.get('skip_on_lmt_ge'),
                    'md5_match': cli_options.get('skip_on_md5_match'),
                },
                'stdin_as_page_blob_size': cli_options.get(
                    'stdin_as_page_blob_size'),
                'store_file_properties': {
                    'attributes': cli_options.get('file_attributes'),
                    'md5': cli_options.get('file_md5'),
                },
                'strip_components': cli_options.get('strip_components'),
                'vectored_io': {
                    'stripe_chunk_size_bytes': cli_options.get(
                        'stripe_chunk_size_bytes'),
                    'distribution_mode': cli_options.get('distribution_mode'),
                },
            },
        }
    count = 0
    if arg['source'] is None:
        arg.pop('source')
        count += 1
    if arg['destination'] is None:
        arg.pop('destination')
        count += 1
    if count == 1:
        if action == TransferAction.Synccopy:
            raise ValueError(
                '--remote-path and --sync-copy-dest-remote-path must be '
                'specified together through the commandline')
        else:
            raise ValueError(
                '--local-path and --remote-path must be specified together '
                'through the commandline')
    if 'accounts' in azstorage:
        cli_options['azure_storage'] = azstorage
    cli_options[action.name.lower()] = arg


def _merge_setting(cli_options, conf, name, name_cli=None, default=None):
    # type: (dict, dict, str, str, Any) -> Any
    """Merge a setting, preferring the CLI option if set
    :param dict cli_options: cli options
    :param dict conf: configuration sub-block
    :param str name: key name
    :param str name_cli: override key name for cli_options
    :param Any default: default value to set if missing
    :rtype: Any
    :return: merged setting value
    """
    val = cli_options.get(name_cli or name)
    if val is None:
        val = conf.get(name, default)
    return val


def merge_global_settings(config, cli_options):
    # type: (dict, dict) -> None
    """Merge "global" CLI options into main config
    :param dict config: config dict
    :param dict cli_options: cli options
    """
    # check for valid version from YAML
    if (not blobxfer.util.is_none_or_empty(config) and
            ('version' not in config or
             config['version'] not in _SUPPORTED_YAML_CONFIG_VERSIONS)):
        raise ValueError('"version" not specified in YAML config or invalid')
    # get action
    action = cli_options['_action']
    if (action != TransferAction.Upload.name.lower() and
            action != TransferAction.Download.name.lower() and
            action != TransferAction.Synccopy.name.lower()):
        raise ValueError('invalid action: {}'.format(action))
    # merge credentials
    if 'azure_storage' in cli_options:
        if 'azure_storage' not in config:
            config['azure_storage'] = {}
        config['azure_storage'] = blobxfer.util.merge_dict(
            config['azure_storage'], cli_options['azure_storage'])
    if ('azure_storage' not in config or
            blobxfer.util.is_none_or_empty(config['azure_storage'])):
        raise ValueError('azure storage settings not specified')
    # create action options
    if action not in config:
        config[action] = []
    # append full specs, if they exist
    if action in cli_options:
        if 'source' in cli_options[action]:
            srcdst = {
                'source': cli_options[action]['source'],
                'destination': cli_options[action]['destination'],
            }
            cli_options[action].pop('source')
            cli_options[action].pop('destination')
            config[action].append(srcdst)
    # merge general and concurrency options
    if 'options' not in config:
        config['options'] = {}
    if 'concurrency' not in config['options']:
        config['options']['concurrency'] = {}
    if 'timeout' not in config['options']:
        config['options']['timeout'] = {}
    if 'proxy' not in config['options']:
        config['options']['proxy'] = {}
    options = {
        'enable_azure_storage_logger': _merge_setting(
            cli_options, config['options'], 'enable_azure_storage_logger'),
        'log_file': _merge_setting(cli_options, config['options'], 'log_file'),
        'progress_bar': _merge_setting(
            cli_options, config['options'], 'progress_bar', default=True),
        'resume_file': _merge_setting(
            cli_options, config['options'], 'resume_file'),
        'timeout': {
            'connect': _merge_setting(
                cli_options, config['options']['timeout'], 'connect',
                name_cli='timeout'),
            'read': _merge_setting(
                cli_options, config['options']['timeout'], 'read',
                name_cli='timeout'),
            'max_retries': _merge_setting(
                cli_options, config['options']['timeout'], 'max_retries',
                default=1000),
        },
        'verbose': _merge_setting(
            cli_options, config['options'], 'verbose', default=False),
        'quiet': _merge_setting(
            cli_options, config['options'], 'quiet', default=False),
        'concurrency': {
            'crypto_processes': _merge_setting(
                cli_options, config['options']['concurrency'],
                'crypto_processes', default=0),
            'disk_threads': _merge_setting(
                cli_options, config['options']['concurrency'],
                'disk_threads', default=0),
            'md5_processes': _merge_setting(
                cli_options, config['options']['concurrency'],
                'md5_processes', default=0),
            'transfer_threads': _merge_setting(
                cli_options, config['options']['concurrency'],
                'transfer_threads', default=0),
        },
        'proxy': {
            'host': _merge_setting(
                cli_options, config['options']['proxy'], 'host',
                name_cli='proxy_host'),
            'username': _merge_setting(
                cli_options, config['options']['proxy'], 'username',
                name_cli='proxy_username'),
            'password': _merge_setting(
                cli_options, config['options']['proxy'], 'password',
                name_cli='proxy_password'),
        }
    }
    config['options'] = options
    cli_options = cli_options[action]


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
    endpoint = config['azure_storage'].get('endpoint') or 'core.windows.net'
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
    conc = config['options']['concurrency']
    # split http proxy host into host:port
    proxy = None
    if blobxfer.util.is_not_empty(config['options']['proxy']['host']):
        tmp = config['options']['proxy']['host'].split(':')
        if len(tmp) != 2:
            raise ValueError('Proxy host is malformed: host should be ip:port')
        username = config['options']['proxy']['username']
        if blobxfer.util.is_none_or_empty(username):
            username = None
        password = config['options']['proxy']['password']
        if blobxfer.util.is_none_or_empty(password):
            password = None
        proxy = blobxfer.models.options.HttpProxy(
            host=tmp[0],
            port=int(tmp[1]),
            username=username,
            password=password,
        )
    return blobxfer.models.options.General(
        concurrency=blobxfer.models.options.Concurrency(
            crypto_processes=conc['crypto_processes'],
            disk_threads=conc['disk_threads'],
            md5_processes=conc['md5_processes'],
            transfer_threads=conc['transfer_threads'],
            action=action.value[0],
        ),
        log_file=config['options']['log_file'],
        progress_bar=config['options']['progress_bar'],
        resume_file=config['options']['resume_file'],
        timeout=blobxfer.models.options.Timeout(
            connect=config['options']['timeout']['connect'],
            read=config['options']['timeout']['read'],
            max_retries=config['options']['timeout']['max_retries'],
        ),
        verbose=config['options']['verbose'],
        quiet=config['options']['quiet'],
        proxy=proxy,
    )


def create_download_specifications(ctx_cli_options, config):
    # type: (dict, dict) -> List[blobxfer.models.download.Specification]
    """Create a list of Download Specification objects from configuration
    :param dict ctx_cli_options: cli options
    :param dict config: config dict
    :rtype: list
    :return: list of Download Specification objects
    """
    cli_conf = ctx_cli_options[ctx_cli_options['_action']]
    cli_options = cli_conf['options']
    specs = []
    for conf in config['download']:
        if 'options' in conf:
            conf_options = conf['options']
        else:
            conf_options = {}
        # create download options
        mode = _merge_setting(
            cli_options, conf_options, 'mode', default='auto').lower()
        if mode == 'auto':
            mode = blobxfer.models.azure.StorageModes.Auto
        elif mode == 'append':
            mode = blobxfer.models.azure.StorageModes.Append
        elif mode == 'block':
            mode = blobxfer.models.azure.StorageModes.Block
        elif mode == 'file':
            mode = blobxfer.models.azure.StorageModes.File
        elif mode == 'page':
            mode = blobxfer.models.azure.StorageModes.Page
        else:
            raise ValueError('unknown mode: {}'.format(mode))
        # load RSA private key PEM file if specified
        rpk = _merge_setting(
            cli_options, conf_options, 'rsa_private_key', default=None)
        if blobxfer.util.is_not_empty(rpk):
            rpkp = _merge_setting(
                cli_options, conf_options, 'rsa_private_key_passphrase',
                default=None)
            rpk = blobxfer.operations.crypto.load_rsa_private_key_file(
                rpk, rpkp)
        else:
            rpk = None
        # create specification
        conf_sod = conf_options.get('skip_on', {})
        cli_sod = cli_options['skip_on']
        ds = blobxfer.models.download.Specification(
            download_options=blobxfer.models.options.Download(
                check_file_md5=_merge_setting(
                    cli_options, conf_options, 'check_file_md5',
                    default=False),
                chunk_size_bytes=_merge_setting(
                    cli_options, conf_options, 'chunk_size_bytes',
                    default=0),
                delete_extraneous_destination=_merge_setting(
                    cli_options, conf_options,
                    'delete_extraneous_destination', default=False),
                mode=mode,
                overwrite=_merge_setting(
                    cli_options, conf_options, 'overwrite', default=True),
                recursive=_merge_setting(
                    cli_options, conf_options, 'recursive', default=True),
                rename=_merge_setting(
                    cli_options, conf_options, 'rename', default=False),
                restore_file_attributes=_merge_setting(
                    cli_options, conf_options, 'restore_file_attributes',
                    default=False),
                rsa_private_key=rpk,
                strip_components=_merge_setting(
                    cli_options, conf_options, 'strip_components',
                    default=0),
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=_merge_setting(
                    cli_sod, conf_sod, 'filesize_match', default=False),
                lmt_ge=_merge_setting(
                    cli_sod, conf_sod, 'lmt_ge', default=False),
                md5_match=_merge_setting(
                    cli_sod, conf_sod, 'md5_match', default=False),
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
            incl = _merge_setting(cli_conf, conf, 'include', default=None)
            if blobxfer.util.is_not_empty(incl):
                asp.add_includes(incl)
            excl = _merge_setting(cli_conf, conf, 'exclude', default=None)
            if blobxfer.util.is_not_empty(excl):
                asp.add_excludes(excl)
            ds.add_azure_source_path(asp)
        # append spec to list
        specs.append(ds)
    return specs


def create_synccopy_specifications(ctx_cli_options, config):
    # type: (dict, dict) -> List[blobxfer.models.synccopy.Specification]
    """Create a list of SyncCopy Specification objects from configuration
    :param dict ctx_cli_options: cli options
    :param dict config: config dict
    :rtype: list
    :return: list of SyncCopy Specification objects
    """
    cli_conf = ctx_cli_options[ctx_cli_options['_action']]
    cli_options = cli_conf['options']
    specs = []
    for conf in config['synccopy']:
        if 'options' in conf:
            conf_options = conf['options']
        else:
            conf_options = {}
        # get source mode
        mode = _merge_setting(
            cli_options, conf_options, 'mode', default='auto').lower()
        if mode == 'auto':
            mode = blobxfer.models.azure.StorageModes.Auto
        elif mode == 'append':
            mode = blobxfer.models.azure.StorageModes.Append
        elif mode == 'block':
            mode = blobxfer.models.azure.StorageModes.Block
        elif mode == 'file':
            mode = blobxfer.models.azure.StorageModes.File
        elif mode == 'page':
            mode = blobxfer.models.azure.StorageModes.Page
        else:
            raise ValueError('unknown source mode: {}'.format(mode))
        # get destination mode
        destmode = _merge_setting(
            cli_options, conf_options, 'dest_mode', name_cli='dest_mode')
        if blobxfer.util.is_none_or_empty(destmode):
            destmode = mode
        else:
            destmode = destmode.lower()
            if destmode == 'auto':
                destmode = blobxfer.models.azure.StorageModes.Auto
            elif destmode == 'append':
                destmode = blobxfer.models.azure.StorageModes.Append
            elif destmode == 'block':
                destmode = blobxfer.models.azure.StorageModes.Block
            elif destmode == 'file':
                destmode = blobxfer.models.azure.StorageModes.File
            elif destmode == 'page':
                destmode = blobxfer.models.azure.StorageModes.Page
            else:
                raise ValueError('unknown dest mode: {}'.format(destmode))
        # create specification
        conf_sod = conf_options.get('skip_on', {})
        cli_sod = cli_options['skip_on']
        scs = blobxfer.models.synccopy.Specification(
            synccopy_options=blobxfer.models.options.SyncCopy(
                access_tier=_merge_setting(
                    cli_options, conf_options, 'access_tier', default=None),
                delete_extraneous_destination=_merge_setting(
                    cli_options, conf_options,
                    'delete_extraneous_destination', default=False),
                dest_mode=destmode,
                mode=mode,
                overwrite=_merge_setting(
                    cli_options, conf_options, 'overwrite', default=True),
                recursive=_merge_setting(
                    cli_options, conf_options, 'recursive', default=True),
                rename=_merge_setting(
                    cli_options, conf_options, 'rename', default=False),
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=_merge_setting(
                    cli_sod, conf_sod, 'filesize_match', default=False),
                lmt_ge=_merge_setting(
                    cli_sod, conf_sod, 'lmt_ge', default=False),
                md5_match=_merge_setting(
                    cli_sod, conf_sod, 'md5_match', default=False),
            ),
        )
        # create remote source paths
        for src in conf['source']:
            sa = next(iter(src))
            asp = blobxfer.operations.azure.SourcePath()
            asp.add_path_with_storage_account(src[sa], sa)
            incl = _merge_setting(cli_conf, conf, 'include', default=None)
            if blobxfer.util.is_not_empty(incl):
                asp.add_includes(incl)
            excl = _merge_setting(cli_conf, conf, 'exclude', default=None)
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


def create_upload_specifications(ctx_cli_options, config):
    # type: (dict, dict) -> List[blobxfer.models.upload.Specification]
    """Create a list of Upload Specification objects from configuration
    :param dict ctx_cli_options: cli options
    :param dict config: config dict
    :rtype: list
    :return: list of Upload Specification objects
    """
    cli_conf = ctx_cli_options[ctx_cli_options['_action']]
    cli_options = cli_conf['options']
    specs = []
    for conf in config['upload']:
        if 'options' in conf:
            conf_options = conf['options']
        else:
            conf_options = {}
        # create upload options
        mode = _merge_setting(
            cli_options, conf_options, 'mode', default='auto').lower()
        if mode == 'auto':
            mode = blobxfer.models.azure.StorageModes.Auto
        elif mode == 'append':
            mode = blobxfer.models.azure.StorageModes.Append
        elif mode == 'block':
            mode = blobxfer.models.azure.StorageModes.Block
        elif mode == 'file':
            mode = blobxfer.models.azure.StorageModes.File
        elif mode == 'page':
            mode = blobxfer.models.azure.StorageModes.Page
        else:
            raise ValueError('unknown mode: {}'.format(mode))
        # load RSA public key PEM if specified
        rpk = _merge_setting(cli_options, conf_options, 'rsa_public_key')
        if blobxfer.util.is_not_empty(rpk):
            rpk = blobxfer.operations.crypto.load_rsa_public_key_file(rpk)
        if rpk is None:
            # load RSA private key PEM file if specified
            rpk = _merge_setting(
                cli_options, conf_options, 'rsa_private_key')
            if blobxfer.util.is_not_empty(rpk):
                rpkp = _merge_setting(
                    cli_options, conf_options, 'rsa_private_key_passphrase')
                rpk = blobxfer.operations.crypto.load_rsa_private_key_file(
                    rpk, rpkp)
                rpk = rpk.public_key()
            else:
                rpk = None
        # create local source paths
        lsp = blobxfer.models.upload.LocalSourcePath()
        lsp.add_paths(conf['source'])
        incl = _merge_setting(cli_conf, conf, 'include', default=None)
        if blobxfer.util.is_not_empty(incl):
            lsp.add_includes(incl)
        excl = _merge_setting(cli_conf, conf, 'exclude', default=None)
        if blobxfer.util.is_not_empty(excl):
            lsp.add_excludes(excl)
        # create specification
        conf_sfp = conf_options.get('store_file_properties', {})
        cli_sfp = cli_options['store_file_properties']
        conf_vio = conf_options.get('vectored_io', {})
        cli_vio = cli_options['vectored_io']
        conf_sod = conf_options.get('skip_on', {})
        cli_sod = cli_options['skip_on']
        us = blobxfer.models.upload.Specification(
            upload_options=blobxfer.models.options.Upload(
                access_tier=_merge_setting(
                    cli_options, conf_options, 'access_tier', default=None),
                chunk_size_bytes=_merge_setting(
                    cli_options, conf_options, 'chunk_size_bytes',
                    default=0),
                delete_extraneous_destination=_merge_setting(
                    cli_options, conf_options,
                    'delete_extraneous_destination', default=False),
                mode=mode,
                one_shot_bytes=_merge_setting(
                    cli_options, conf_options, 'one_shot_bytes', default=0),
                overwrite=_merge_setting(
                    cli_options, conf_options, 'overwrite', default=True),
                recursive=_merge_setting(
                    cli_options, conf_options, 'recursive', default=True),
                rename=_merge_setting(
                    cli_options, conf_options, 'rename', default=False),
                rsa_public_key=rpk,
                store_file_properties=blobxfer.models.options.FileProperties(
                    attributes=_merge_setting(
                        cli_sfp, conf_sfp, 'attributes', default=False),
                    md5=_merge_setting(
                        cli_sfp, conf_sfp, 'md5', default=False),
                ),
                stdin_as_page_blob_size=_merge_setting(
                    cli_options, conf_options, 'stdin_as_page_blob_size',
                    default=0),
                strip_components=_merge_setting(
                    cli_options, conf_options, 'strip_components',
                    default=0),
                vectored_io=blobxfer.models.options.VectoredIo(
                    stripe_chunk_size_bytes=_merge_setting(
                        cli_vio, conf_vio, 'stripe_chunk_size_bytes',
                        default=1073741824),
                    distribution_mode=blobxfer.
                    models.upload.VectoredIoDistributionMode(
                        _merge_setting(
                            cli_vio, conf_vio, 'distribution_mode',
                            default='disabled').lower()),
                ),
            ),
            skip_on_options=blobxfer.models.options.SkipOn(
                filesize_match=_merge_setting(
                    cli_sod, conf_sod, 'filesize_match', default=False),
                lmt_ge=_merge_setting(
                    cli_sod, conf_sod, 'lmt_ge', default=False),
                md5_match=_merge_setting(
                    cli_sod, conf_sod, 'md5_match', default=False),
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
