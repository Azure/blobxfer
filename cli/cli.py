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
import multiprocessing
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
try:
    import cli.settings as settings
except (SystemError, ImportError):  # noqa
    try:
        from . import settings
    except (SystemError, ImportError):  # noqa
        # for local testing
        import settings

# create logger
logger = logging.getLogger('blobxfer')
# global defines
_CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


class CliContext(object):
    """CliContext class: holds context for CLI commands"""
    def __init__(self):
        """Ctor for CliContext"""
        self.config = None
        self.cli_options = {}
        self.credentials = None
        self.general_options = None
        self.show_config = False

    def initialize(self, action):
        # type: (CliContext, settings.TransferAction) -> None
        """Initialize context
        :param CliContext self: this
        :param settings.TransferAction action: transfer action
        """
        self._init_config()
        self.general_options = settings.create_general_options(
            self.config, action)
        self.credentials = settings.create_azure_storage_credentials(
            self.config, self.general_options)

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
                    ruamel.yaml.load(f, Loader=ruamel.yaml.RoundTripLoader),
                    self.config)

    def _init_config(self):
        # type: (CliContext) -> None
        """Initializes configuration of the context
        :param CliContext self: this
        """
        # load yaml config file into memory
        if blobxfer.util.is_not_empty(self.cli_options['yaml_config']):
            yaml_config = pathlib.Path(self.cli_options['yaml_config'])
            self._read_yaml_file(yaml_config)
        if self.config is None:
            self.config = {}
        # merge "global" cli options with config
        settings.merge_global_settings(self.config, self.cli_options)
        # set log file if specified
        logfile = self.config['options'].get('log_file', None)
        blobxfer.util.setup_logger(logger, logfile)
        # set verbose logging
        if self.config['options'].get('verbose', False):
            blobxfer.util.set_verbose_logger_handlers()
        # set azure storage logging level
        azstorage_logger = logging.getLogger('azure.storage')
        if self.config['options'].get('enable_azure_storage_logger', False):
            blobxfer.util.setup_logger(azstorage_logger, logfile)
            azstorage_logger.setLevel(logging.INFO)
        else:
            # disable azure storage logging: setting logger level to CRITICAL
            # effectively disables logging from azure storage
            azstorage_logger.setLevel(logging.CRITICAL)
        # output mixed config
        if self.show_config:
            logger.debug('config: \n{}'.format(
                json.dumps(self.config, indent=4)))
            logger.debug('cli config: \n{}'.format(
                json.dumps(
                    self.cli_options[self.cli_options['_action']],
                    indent=4, sort_keys=True)))
        del self.show_config


# create a pass decorator for shared context between commands
pass_cli_context = click.make_pass_decorator(CliContext, ensure=True)


def _config_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['yaml_config'] = value
        return value
    return click.option(
        '--config',
        expose_value=False,
        default=None,
        help='YAML configuration file',
        envvar='BLOBXFER_CONFIG_FILE',
        callback=callback)(f)


def _crypto_processes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['crypto_processes'] = value
        return value
    return click.option(
        '--crypto-processes',
        expose_value=False,
        type=int,
        default=None,
        help='Concurrent crypto processes (download only)',
        callback=callback)(f)


def _disk_threads_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['disk_threads'] = value
        return value
    return click.option(
        '--disk-threads',
        expose_value=False,
        type=int,
        default=None,
        help='Concurrent disk threads',
        callback=callback)(f)


def _enable_azure_storage_logger_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['enable_azure_storage_logger'] = value
        return value
    return click.option(
        '--enable-azure-storage-logger',
        expose_value=False,
        is_flag=True,
        default=False,
        help='Enable Azure Storage logger output [False]',
        callback=callback)(f)


def _log_file_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['log_file'] = value
        return value
    return click.option(
        '--log-file',
        expose_value=False,
        default=None,
        help='Log to file specified; this must be specified for progress '
        'bar to show',
        callback=callback)(f)


def _max_retries_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['max_retries'] = value
        return value
    return click.option(
        '--max-retries',
        expose_value=False,
        type=int,
        default=None,
        help='Maximum number of retries for a request; negative values are '
        'unlimited [10]',
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
        default=None,
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
        default=None,
        help='Display progress bar instead of console logs; log file must '
        'be specified [True]',
        callback=callback)(f)


def _proxy_host_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['proxy_host'] = value
        return value
    return click.option(
        '--proxy-host',
        expose_value=False,
        default=None,
        help='Proxy host in the format of IP:Port',
        envvar='BLOBXFER_PROXY_HOST',
        callback=callback)(f)


def _proxy_password_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['proxy_password'] = value
        return value
    return click.option(
        '--proxy-password',
        expose_value=False,
        default=None,
        help='Proxy password',
        envvar='BLOBXFER_PROXY_PASSWORD',
        callback=callback)(f)


def _proxy_username_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['proxy_username'] = value
        return value
    return click.option(
        '--proxy-username',
        expose_value=False,
        default=None,
        help='Proxy username',
        envvar='BLOBXFER_PROXY_USERNAME',
        callback=callback)(f)


def _resume_file_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['resume_file'] = value
        return value
    return click.option(
        '--resume-file',
        expose_value=False,
        default=None,
        help='Save or use resume file specified',
        callback=callback)(f)


def _show_config_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.show_config = value
        return value
    return click.option(
        '--show-config',
        expose_value=False,
        is_flag=True,
        help='Show configuration',
        callback=callback)(f)


def _timeout_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['timeout'] = value
        return value
    return click.option(
        '--timeout',
        expose_value=False,
        type=float,
        default=None,
        help='Timeout, in seconds, applied to both connect and read '
        'operations',
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
        default=None,
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
        default=None,
        help='Verbose output',
        callback=callback)(f)


def _quiet_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['quiet'] = value
        return value
    return click.option(
        '-q', '--quiet',
        expose_value=False,
        is_flag=True,
        default=None,
        help='Quiet mode',
        callback=callback)(f)


def _local_resource_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['local_resource'] = value
        return value
    return click.option(
        '--local-path',
        expose_value=False,
        default=None,
        help='Local path; use - for stdin',
        callback=callback)(f)


def _storage_account_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['storage_account'] = value
        return value
    return click.option(
        '--storage-account',
        expose_value=False,
        default=None,
        help='Storage account name',
        envvar='BLOBXFER_STORAGE_ACCOUNT',
        callback=callback)(f)


def _remote_path_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['remote_path'] = value
        return value
    return click.option(
        '--remote-path',
        expose_value=False,
        default=None,
        help='Remote path on Azure Storage',
        callback=callback)(f)


def common_options(f):
    f = _verbose_option(f)
    f = _transfer_threads_option(f)
    f = _timeout_option(f)
    f = _show_config_option(f)
    f = _resume_file_option(f)
    f = _quiet_option(f)
    f = _proxy_username_option(f)
    f = _proxy_password_option(f)
    f = _proxy_host_option(f)
    f = _progress_bar_option(f)
    f = _md5_processes_option(f)
    f = _max_retries_option(f)
    f = _log_file_option(f)
    f = _enable_azure_storage_logger_option(f)
    f = _disk_threads_option(f)
    f = _crypto_processes_option(f)
    f = _config_option(f)
    return f


def upload_download_options(f):
    f = _remote_path_option(f)
    f = _storage_account_option(f)
    f = _local_resource_option(f)
    return f


def _access_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['access_key'] = value
        return value
    return click.option(
        '--storage-account-key',
        expose_value=False,
        default=None,
        help='Storage account access key',
        envvar='BLOBXFER_STORAGE_ACCOUNT_KEY',
        callback=callback)(f)


def _access_tier_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['access_tier'] = value
        return value
    return click.option(
        '--access-tier',
        expose_value=False,
        default=None,
        help='Access tier to apply to target (block blob only)',
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
        default=None,
        help='Block or chunk size in bytes; set to 0 for auto-select '
        'on upload [0]',
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
        default=None,
        help='Delete extraneous files on target [False]',
        callback=callback)(f)


def _distribution_mode(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['distribution_mode'] = value
        return value
    return click.option(
        '--distribution-mode',
        expose_value=False,
        default=None,
        help='Vectored IO distribution mode: disabled, replica, '
        'stripe [disabled]',
        callback=callback)(f)


def _endpoint_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['endpoint'] = value
        return value
    return click.option(
        '--endpoint',
        expose_value=False,
        default=None,
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
        multiple=True,
        default=None,
        help='Exclude pattern',
        callback=callback)(f)


def _file_attributes(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['file_attributes'] = value
        return value
    return click.option(
        '--file-attributes/--no-file-attributes',
        expose_value=False,
        default=None,
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
        default=None,
        help='Compute file MD5 [False]',
        callback=callback)(f)


def _include_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['include'] = value
        return value
    return click.option(
        '--include',
        expose_value=False,
        multiple=True,
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
        default=None,
        help='Transfer mode: auto, append, block, file, page [auto]',
        callback=callback)(f)


def _one_shot_bytes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['one_shot_bytes'] = value
        return value
    return click.option(
        '--one-shot-bytes',
        expose_value=False,
        type=int,
        default=None,
        help='File sizes less than or equal to the specified byte threshold '
        'will be uploaded as one-shot for block blobs; the valid range that '
        'can be specified is 0 to 256MiB [0]',
        callback=callback)(f)


def _overwrite_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['overwrite'] = value
        return value
    return click.option(
        '--overwrite/--no-overwrite',
        expose_value=False,
        default=None,
        help='Overwrite destination if exists. For append blobs, '
        '--no-overwrite will append to any existing blob. [True]',
        callback=callback)(f)


def _recursive_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['recursive'] = value
        return value
    return click.option(
        '--recursive/--no-recursive',
        expose_value=False,
        default=None,
        help='Recursive [True]',
        callback=callback)(f)


def _rename_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['rename'] = value
        return value
    return click.option(
        '--rename',
        expose_value=False,
        is_flag=True,
        default=None,
        help='Rename to specified destination for a single object. '
        'Automatically enabled with stdin source. [False]',
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
        help='RSA private key PEM file',
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
        help='RSA public key PEM file',
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
        default=None,
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
        default=None,
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
        default=None,
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
        default=None,
        help='Skip on MD5 match [False]',
        callback=callback)(f)


def _stdin_as_page_blob_size_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['stdin_as_page_blob_size'] = value
        return value
    return click.option(
        '--stdin-as-page-blob-size',
        expose_value=False,
        type=int,
        default=None,
        help='Size of page blob with input from stdin [0]',
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
        default=None,
        help='Strip leading file path components: local path for upload '
        'or remote path for download [0]',
        callback=callback)(f)


def _stripe_chunk_size_bytes_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['stripe_chunk_size_bytes'] = value
        return value
    return click.option(
        '--stripe-chunk-size-bytes',
        expose_value=False,
        type=int,
        default=None,
        help='Vectored IO stripe width in bytes [1073741824]',
        callback=callback)(f)


def _sync_copy_dest_access_key_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_access_key'] = value
        return value
    return click.option(
        '--sync-copy-dest-storage-account-key',
        expose_value=False,
        default=None,
        help='Storage account access key for synccopy destination',
        envvar='BLOBXFER_SYNC_COPY_DEST_STORAGE_ACCOUNT_KEY',
        callback=callback)(f)


def _sync_copy_dest_mode_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_mode'] = value
        return value
    return click.option(
        '--sync-copy-dest-mode',
        expose_value=False,
        default=None,
        help='Mode for synccopy destination',
        callback=callback)(f)


def _sync_copy_dest_remote_path_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_remote_path'] = value
        return value
    return click.option(
        '--sync-copy-dest-remote-path',
        expose_value=False,
        default=None,
        help='Remote path on Azure Storage for synccopy destination',
        callback=callback)(f)


def _sync_copy_dest_sas_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_sas'] = value
        return value
    return click.option(
        '--sync-copy-dest-sas',
        expose_value=False,
        default=None,
        help='Shared access signature for synccopy destination',
        envvar='BLOBXFER_SYNC_COPY_DEST_SAS',
        callback=callback)(f)


def _sync_copy_dest_storage_account_option(f):
    def callback(ctx, param, value):
        clictx = ctx.ensure_object(CliContext)
        clictx.cli_options['sync_copy_dest_storage_account'] = value
        return value
    return click.option(
        '--sync-copy-dest-storage-account',
        expose_value=False,
        default=None,
        help='Storage account name for synccopy destination',
        envvar='BLOBXFER_SYNC_COPY_DEST_STORAGE_ACCOUNT',
        callback=callback)(f)


def upload_options(f):
    f = _stripe_chunk_size_bytes_option(f)
    f = _strip_components_option(f)
    f = _stdin_as_page_blob_size_option(f)
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _rsa_public_key_option(f)
    f = _rsa_private_key_passphrase_option(f)
    f = _rsa_private_key_option(f)
    f = _rename_option(f)
    f = _recursive_option(f)
    f = _overwrite_option(f)
    f = _one_shot_bytes_option(f)
    f = _mode_option(f)
    f = _include_option(f)
    f = _file_md5_option(f)
    f = _file_attributes(f)
    f = _exclude_option(f)
    f = _endpoint_option(f)
    f = _distribution_mode(f)
    f = _delete_option(f)
    f = _chunk_size_bytes_option(f)
    f = _access_tier_option(f)
    f = _access_key_option(f)
    return f


def download_options(f):
    f = _strip_components_option(f)
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _rsa_private_key_passphrase_option(f)
    f = _rsa_private_key_option(f)
    f = _rename_option(f)
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
    f = _sync_copy_dest_storage_account_option(f)
    f = _sync_copy_dest_sas_option(f)
    f = _sync_copy_dest_remote_path_option(f)
    f = _sync_copy_dest_mode_option(f)
    f = _sync_copy_dest_access_key_option(f)
    f = _storage_account_option(f)
    f = _skip_on_md5_match_option(f)
    f = _skip_on_lmt_ge_option(f)
    f = _skip_on_filesize_match_option(f)
    f = _sas_option(f)
    f = _remote_path_option(f)
    f = _overwrite_option(f)
    f = _mode_option(f)
    f = _include_option(f)
    f = _exclude_option(f)
    f = _endpoint_option(f)
    f = _chunk_size_bytes_option(f)
    f = _access_tier_option(f)
    f = _access_key_option(f)
    return f


@click.group(context_settings=_CONTEXT_SETTINGS)
@click.version_option(version=blobxfer.__version__)
@click.pass_context
def cli(ctx):
    """blobxfer: Azure Storage transfer tool"""
    pass


@cli.command('download')
@upload_download_options
@download_options
@common_options
@pass_cli_context
def download(ctx):
    """Download blobs or files from Azure Storage"""
    settings.add_cli_options(ctx.cli_options, settings.TransferAction.Download)
    ctx.initialize(settings.TransferAction.Download)
    specs = settings.create_download_specifications(
        ctx.cli_options, ctx.config)
    del ctx.cli_options
    for spec in specs:
        blobxfer.api.Downloader(
            ctx.general_options, ctx.credentials, spec
        ).start()


@cli.command('synccopy')
@sync_copy_options
@common_options
@pass_cli_context
def synccopy(ctx):
    """Synchronously copy blobs or files between Azure Storage accounts"""
    settings.add_cli_options(ctx.cli_options, settings.TransferAction.Synccopy)
    ctx.initialize(settings.TransferAction.Synccopy)
    specs = settings.create_synccopy_specifications(
        ctx.cli_options, ctx.config)
    del ctx.cli_options
    for spec in specs:
        blobxfer.api.SyncCopy(
            ctx.general_options, ctx.credentials, spec
        ).start()


@cli.command('upload')
@upload_download_options
@upload_options
@common_options
@pass_cli_context
def upload(ctx):
    """Upload files to Azure Storage"""
    settings.add_cli_options(ctx.cli_options, settings.TransferAction.Upload)
    ctx.initialize(settings.TransferAction.Upload)
    specs = settings.create_upload_specifications(
        ctx.cli_options, ctx.config)
    del ctx.cli_options
    for spec in specs:
        blobxfer.api.Uploader(
            ctx.general_options, ctx.credentials, spec
        ).start()


if __name__ == '__main__':
    multiprocessing.freeze_support()
    cli()
