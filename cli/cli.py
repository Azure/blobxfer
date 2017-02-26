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
from __future__ import absolute_import, division, print_function
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip)
# stdlib imports
import json
import logging
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import click
import ruamel.yaml
# blobxfer library imports
import blobxfer.api
import blobxfer.util
# local imports
import settings

# create logger
logger = logging.getLogger('blobxfer')
blobxfer.util.setup_logger(logger)
# global defines
_CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


class CliContext(object):
    """CliContext class: holds context for CLI commands"""
    def __init__(self):
        """Ctor for CliContext"""
        self.yaml_config = None
        self.config = {}
        self.cli_options = {}
        self.credentials = None
        self.general_options = None

    def initialize(self):
        # type: (CliContext) -> None
        """Initialize context
        :param CliContext self: this
        """
        self._init_config()
        self.credentials = settings.create_azure_storage_credentials(
            self.config)
        self.general_options = settings.create_general_options(self.config)

    def _read_yaml_file(self, yaml_file):
        # type: (CliContext, pathlib.Path) -> None
        """Read a yaml file into self.config
        :param CliContext self: this
        :param pathlib.Path yaml_file: yaml file to load
        """
        with yaml_file.open('r') as f:
            if self.config is None:
                self.config = ruamel.yaml.load(
                    f, Loader=ruamel.yaml.RoundTripLoader)
            else:
                self.config = blobxfer.util.merge_dict(
                    self.config, ruamel.yaml.load(
                        f, Loader=ruamel.yaml.RoundTripLoader))

    def _init_config(self):
        # type: (CliContext) -> None
        """Initializes configuration of the context
        :param CliContext self: this
        """
        # load yaml config file into memory
        if blobxfer.util.is_not_empty(self.yaml_config):
            self.yaml_config = pathlib.Path(self.yaml_config)
            self._read_yaml_file(self.yaml_config)
        # merge cli options with config
        settings.merge_settings(self.config, self.cli_options)
        if self.config['options']['verbose']:
            logger.debug('config: \n' + json.dumps(self.config, indent=4))
        # free mem
        del self.yaml_config
        del self.cli_options


# create a pass decorator for shared context between commands
pass_cli_context = click.make_pass_decorator(CliContext, ensure=True)


def _crypto_processes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['crypto_processes'] = value
        return value
    return click.option(
        '--crypto-processes',
        expose_value=False,
        type=int,
        default=0,
        help='Concurrent crypto processes',
        callback=callback)(f)


def _md5_processes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['md5_processes'] = value
        return value
    return click.option(
        '--md5-processes',
        expose_value=False,
        type=int,
        default=0,
        help='Concurrent MD5 processes',
        callback=callback)(f)


def _progress_bar_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['progress_bar'] = value
        return value
    return click.option(
        '--progress-bar/--no-progress-bar',
        expose_value=False,
        default=True,
        help='Display progress bar',
        callback=callback)(f)


def _timeout_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['timeout'] = value
        return value
    return click.option(
        '--timeout',
        expose_value=False,
        type=int,
        help='Individual chunk transfer timeout',
        callback=callback)(f)


def _transfer_threads_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['transfer_threads'] = value
        return value
    return click.option(
        '--transfer-threads',
        expose_value=False,
        type=int,
        default=0,
        help='Concurrent transfer threads',
        callback=callback)(f)


def _verbose_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['verbose'] = value
        return value
    return click.option(
        '-v', '--verbose',
        expose_value=False,
        is_flag=True,
        help='Verbose output',
        callback=callback)(f)


def common_options(f):
    f = _verbose_option(f)
    f = _transfer_threads_option(f)
    f = _timeout_option(f)
    f = _progress_bar_option(f)
    f = _md5_processes_option(f)
    f = _crypto_processes_option(f)
    return f


def _local_resource_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.local_resource = value
        return value
    return click.argument(
        'local-resource',
        callback=callback)(f)


def _storage_account_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['storage_account'] = value
        return value
    return click.argument(
        'storage-account',
        callback=callback)(f)


def _remote_path_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['remote_path'] = value
        return value
    return click.argument(
        'remote-path',
        callback=callback)(f)


def upload_download_arguments(f):
    f = _remote_path_argument(f)
    f = _storage_account_argument(f)
    f = _local_resource_argument(f)
    return f


def _sync_copy_dest_storage_account_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_storage_account'] = value
        return value
    return click.argument(
        'sync-copy-dest-storage-account',
        callback=callback)(f)


def _sync_copy_dest_remote_path_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_remote_path'] = value
        return value
    return click.argument(
        'sync-copy-dest-remote-path',
        callback=callback)(f)


def sync_copy_arguments(f):
    f = _sync_copy_dest_remote_path_argument(f)
    f = _sync_copy_dest_storage_account_argument(f)
    f = _remote_path_argument(f)
    f = _storage_account_argument(f)
    return f


def _access_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['access_key'] = value
        return value
    return click.option(
        '--access-key',
        expose_value=False,
        help='Storage account access key',
        envvar='BLOBXFER_ACCESS_KEY',
        callback=callback)(f)


def _chunk_size_bytes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['chunk_size_bytes'] = value
        return value
    return click.option(
        '--chunk-size-bytes',
        expose_value=False,
        type=int,
        default=4194304,
        help='Block or chunk size in bytes [4194304]',
        callback=callback)(f)


def _delete_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['delete'] = value
        return value
    return click.option(
        '--delete',
        expose_value=False,
        is_flag=True,
        help='Delete extraneous files on target [False]',
        callback=callback)(f)


def _endpoint_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['endpoint'] = value
        return value
    return click.option(
        '--endpoint',
        expose_value=False,
        default='core.windows.net',
        help='Azure Storage endpoint [core.windows.net]',
        callback=callback)(f)


def _exclude_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['exclude'] = value
        return value
    return click.option(
        '--exclude',
        expose_value=False,
        default=None,
        help='Exclude pattern',
        callback=callback)(f)


def _file_attributes(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['file_attributes'] = value
        return value
    return click.option(
        '--file-attributes',
        expose_value=False,
        is_flag=True,
        help='Store or restore file attributes [False]',
        callback=callback)(f)


def _file_md5_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['file_md5'] = value
        return value
    return click.option(
        '--file-md5/--no-file-md5',
        expose_value=False,
        default=True,
        help='Compute file MD5 [True]',
        callback=callback)(f)


def _include_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['include'] = value
        return value
    return click.option(
        '--include',
        expose_value=False,
        default=None,
        help='Include pattern',
        callback=callback)(f)


def _mode_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['mode'] = value
        return value
    return click.option(
        '--mode',
        expose_value=False,
        default='auto',
        help='Transfer mode: auto, append, block, file, page [auto]',
        callback=callback)(f)


def _overwrite_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['overwrite'] = value
        return value
    return click.option(
        '--overwrite/--no-overwrite',
        expose_value=False,
        default=True,
        help='Overwrite destination if exists [True]',
        callback=callback)(f)


def _recursive_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['recursive'] = value
        return value
    return click.option(
        '--recursive/--no-recursive',
        expose_value=False,
        default=True,
        help='Recursive [True]',
        callback=callback)(f)


def _rsa_private_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['rsa_private_key'] = value
        return value
    return click.option(
        '--rsa-private-key',
        expose_value=False,
        default=None,
        help='RSA private key',
        envvar='BLOBXFER_RSA_PRIVATE_KEY',
        callback=callback)(f)


def _rsa_private_key_passphrase_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['rsa_private_key_passphrase'] = value
        return value
    return click.option(
        '--rsa-private-key-passphrase',
        expose_value=False,
        default=None,
        help='RSA private key passphrase',
        envvar='BLOBXFER_RSA_PRIVATE_KEY_PASSPHRASE',
        callback=callback)(f)


def _rsa_public_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['rsa_public_key'] = value
        return value
    return click.option(
        '--rsa-public-key',
        expose_value=False,
        default=None,
        help='RSA public key',
        envvar='BLOBXFER_RSA_PUBLIC_KEY',
        callback=callback)(f)


def _sas_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sas'] = value
        return value
    return click.option(
        '--sas',
        expose_value=False,
        help='Shared access signature',
        envvar='BLOBXFER_SAS',
        callback=callback)(f)


def _skip_on_filesize_match_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['skip_on_filesize_match'] = value
        return value
    return click.option(
        '--skip-on-filesize-match',
        expose_value=False,
        is_flag=True,
        help='Skip on equivalent file size [False]',
        callback=callback)(f)


def _skip_on_lmt_ge_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['skip_on_lmt_ge'] = value
        return value
    return click.option(
        '--skip-on-lmt-ge',
        expose_value=False,
        is_flag=True,
        help='Skip on last modified time greater than or equal to [False]',
        callback=callback)(f)


def _skip_on_md5_match_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['skip_on_md5_match'] = value
        return value
    return click.option(
        '--skip-on-md5-match',
        expose_value=False,
        is_flag=True,
        help='Skip on MD5 match [False]',
        callback=callback)(f)


def _strip_components_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['strip_components'] = value
        return value
    return click.option(
        '--strip-components',
        expose_value=False,
        type=int,
        default=1,
        help='Strip leading file path components [1]',
        callback=callback)(f)


def _sync_copy_dest_access_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_access_key'] = value
        return value
    return click.option(
        '--sync-copy-dest-access-key',
        expose_value=False,
        help='Storage account access key for synccopy destination',
        envvar='BLOBXFER_SYNC_COPY_DEST_ACCESS_KEY',
        callback=callback)(f)


def _sync_copy_dest_sas_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_sas'] = value
        return value
    return click.option(
        '--sync-copy-dest-sas',
        expose_value=False,
        help='Shared access signature for synccopy destination',
        envvar='BLOBXFER_SYNC_COPY_SAS',
        callback=callback)(f)


def upload_options(f):
    f = _strip_components_option(f)
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _rsa_public_key_option(f)
    f = _rsa_private_key_passphrase_option(f)
    f = _rsa_private_key_option(f)
    f = _recursive_option(f)
    f = _overwrite_option(f)
    f = _mode_option(f)
    f = _include_option(f)
    f = _file_md5_option(f)
    f = _file_attributes(f)
    f = _exclude_option(f)
    f = _endpoint_option(f)
    f = _delete_option(f)
    f = _chunk_size_bytes_option(f)
    f = _access_key_option(f)
    return f


def download_options(f):
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _rsa_private_key_passphrase_option(f)
    f = _rsa_private_key_option(f)
    f = _recursive_option(f)
    f = _overwrite_option(f)
    f = _mode_option(f)
    f = _include_option(f)
    f = _file_md5_option(f)
    f = _file_attributes(f)
    f = _exclude_option(f)
    f = _endpoint_option(f)
    f = _delete_option(f)
    f = _chunk_size_bytes_option(f)
    f = _access_key_option(f)
    return f


def sync_copy_options(f):
    f = _sync_copy_dest_sas_option(f)
    f = _sync_copy_dest_access_key_option(f)
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _overwrite_option(f)
    f = _mode_option(f)
    f = _include_option(f)
    f = _exclude_option(f)
    f = _endpoint_option(f)
    f = _chunk_size_bytes_option(f)
    f = _access_key_option(f)
    return f


def _config_argument(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.yaml_config = value
        return value
    return click.argument(
        'config',
        callback=callback)(f)


def config_arguments(f):
    f = _config_argument(f)
    return f


@click.group(context_settings=_CONTEXT_SETTINGS)
@click.version_option(version=blobxfer.__version__)
@click.pass_context
def cli(ctx):
    """Blobxfer-CLI: Azure Storage transfer tool"""
    pass


@cli.command('download')
@upload_download_arguments
@download_options
@common_options
@pass_cli_context
def download(ctx, local_resource, storage_account, remote_path):
    """Download blobs or files from Azure Storage"""
    settings.add_cli_options(
        ctx.cli_options, settings.TransferAction.Download, local_resource,
        storage_account, remote_path)
    ctx.initialize()
    specs = settings.create_download_specifications(ctx.config)
    for spec in specs:
        blobxfer.api.Downloader(
            ctx.general_options, ctx.credentials, spec
        ).start()


@cli.command('synccopy')
@sync_copy_arguments
@sync_copy_options
@common_options
@pass_cli_context
def synccopy(
        ctx, local_resource, storage_account, remote_path,
        sync_copy_dest_storage_account, sync_copy_dest_remote_path):
    """Synchronously copy blobs between Azure Storage accounts"""
    settings.add_cli_options(
        ctx.cli_options, settings.TransferAction.Synccopy, local_resource,
        storage_account, remote_path, sync_copy_dest_storage_account,
        sync_copy_dest_remote_path)
    ctx.initialize()
    raise NotImplementedError()


@cli.command('upload')
@upload_download_arguments
@upload_options
@common_options
@pass_cli_context
def upload(ctx, local_resource, storage_account, remote_path):
    """Upload files to Azure Storage"""
    settings.add_cli_options(
        ctx.cli_options, settings.TransferAction.Upload, local_resource,
        storage_account, remote_path)
    ctx.initialize()
    blobxfer.api.upload_block()


@cli.group()
@pass_cli_context
def useconfig(ctx):
    """Use config file for transfer"""
    pass


@useconfig.command('upload')
@config_arguments
@common_options
@pass_cli_context
def useconfig_upload(ctx):
    """Upload files to Azure File Storage"""
    ctx.initialize()
    raise NotImplementedError()


if __name__ == '__main__':
    cli()