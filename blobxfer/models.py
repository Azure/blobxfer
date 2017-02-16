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
import collections
import enum
import fnmatch
import logging
import os
try:
    import pathlib2 as pathlib
except ImportError:
    import pathlib
# non-stdlib imports
# local imports
from .api import (
    create_append_blob_client,
    create_block_blob_client,
    create_file_client,
    create_page_blob_client,
)
import blobxfer.blob.operations
import blobxfer.crypto
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


# enums
class AzureStorageModes(enum.Enum):
    Auto = 1
    Append = 2
    Block = 3
    File = 4
    Page = 5


# named tuples
GeneralOptions = collections.namedtuple(
    'GeneralOptions', [
        'progress_bar',
        'timeout_sec',
        'verbose',
    ]
)
VectoredIoOptions = collections.namedtuple(
    'VectoredIoOptions', [
        'stripe_chunk_size_bytes',
        'multi_storage_account_distribution_mode',
    ]
)
SkipOnOptions = collections.namedtuple(
    'SkipOnOptions', [
        'filesize_match',
        'lmt_ge',
        'md5_match',
    ]
)
UploadOptions = collections.namedtuple(
    'UploadOptions', [
        'chunk_size_bytes',
        'delete_extraneous_destination',
        'mode',
        'overwrite',
        'recursive',
        'rsa_private_key',
        'rsa_public_key',
        'store_file_attributes',
        'store_file_md5',
        'strip_components',
        'vectored_io',
        'split_size_bytes',
    ]
)
DownloadOptions = collections.namedtuple(
    'DownloadOptions', [
        'check_file_md5',
        'delete_extraneous_destination',
        'mode',
        'overwrite',
        'recursive',
        'restore_file_attributes',
        'rsa_private_key',
    ]
)
SyncCopyOptions = collections.namedtuple(
    'SyncCopyOptions', [
        'exclude',
        'include',
        'mode',
        'overwrite',
        'skip_on',
    ]
)
LocalPath = collections.namedtuple(
    'LocalPath', [
        'parent_path', 'relative_path'
    ]
)


class AzureStorageCredentials(object):
    """Azure Storage Credentials"""
    def __init__(self):
        # type: (AzureStorageCredentials) -> None
        """Ctor for AzureStorageCredentials"""
        self._storage_accounts = {}

    def add_storage_account(self, name, key, endpoint):
        # type: (AzureStorageCredentials, str, str, str) -> None
        """Add a storage account
        :param AzureStorageCredentials self: this
        :param str name: name of storage account to store
        :param str key: storage key or sas
        :param str endpoint: endpoint
        """
        if name in self._storage_accounts:
            raise ValueError(
                '{} already exists in storage accounts'.format(name))
        self._storage_accounts[name] = AzureStorageAccount(name, key, endpoint)

    def get_storage_account(self, name):
        # type: (AzureStorageCredentials, str) -> AzureStorageAccount
        """Get storage account details
        :param AzureStorageCredentials self: this
        :param str name: name of storage account to retrieve
        :rtype: AzureStorageAccount
        :return: storage account details
        """
        return self._storage_accounts[name]


class AzureStorageAccount(object):
    """Azure Storage Account"""
    def __init__(self, name, key, endpoint):
        # type: (AzureStorageAccount, str, str, str) -> None
        """Ctor for AzureStorageAccount
        :param str name: name of storage account
        :param str key: storage key or sas
        :param str endpoint: endpoint
        """
        self._append_blob_client = None
        self._block_blob_client = None
        self._file_client = None
        self._page_blob_client = None
        self.name = name
        self.key = key
        self.endpoint = endpoint
        self.is_sas = self._key_is_sas(self.key)
        # normalize sas keys
        if self.is_sas and self.key.startswith('?'):
            self.key = self.key[1:]
        self._create_clients()

    @staticmethod
    def _key_is_sas(key):
        # type: (str) -> bool
        """Determine if key is a sas
        :param str key: key to parse
        :rtype: bool
        :return: if key is a sas
        """
        # keys starting with ? are sas keys as ? is not in the base-64
        # character range
        if key.startswith('?'):
            return True
        else:
            # & is not in the base-64 character range, so technically
            # the presence of this character means the key is a sas. however,
            # perform a stronger check for the sig= parameter.
            tmp = key.split('&')
            if len(tmp) == 1:
                return False
            elif any(x.startswith('sig=') for x in tmp):
                return True
        return False

    def _create_clients(self):
        # type: (AzureStorageAccount) -> None
        """Create Azure Storage clients
        :param AzureStorageAccount self: this
        """
        self._append_blob_client = create_append_blob_client(self)
        self._block_blob_client = create_block_blob_client(self)
        self._file_client = create_file_client(self)
        self._page_blob_client = create_page_blob_client(self)

    @property
    def append_blob_client(self):
        # type: (AzureStorageAccount) -> azure.storage.blob.AppendBlobService
        """Get append blob client
        :param AzureStorageAccount self: this
        :rtype: azure.storage.blob.AppendBlobService
        :return: append blob client
        """
        return self._append_blob_client

    @property
    def block_blob_client(self):
        # type: (AzureStorageAccount) -> azure.storage.blob.BlockBlobService
        """Get block blob client
        :param AzureStorageAccount self: this
        :rtype: azure.storage.blob.BlockBlobService
        :return: block blob client
        """
        return self._block_blob_client

    @property
    def file_client(self):
        # type: (AzureStorageAccount) -> azure.storage.file.FileService
        """Get file client
        :param AzureStorageAccount self: this
        :rtype: azure.storage.file.FileService
        :return: file client
        """
        return self._file_client

    @property
    def page_blob_client(self):
        # type: (AzureStorageAccount) -> azure.storage.blob.PageBlobService
        """Get page blob client
        :param AzureStorageAccount self: this
        :rtype: azure.storage.blob.PageBlobService
        :return: page blob client
        """
        return self._page_blob_client


class _BaseSourcePaths(object):
    """Base Source Paths"""
    def __init__(self):
        # type: (_BaseSourcePaths) -> None
        """Ctor for _BaseSourcePaths
        :param _BaseSourcePaths self: this
        """
        self._include = None
        self._exclude = None
        self._paths = []

    @property
    def paths(self):
        # type: (_BaseSourcePaths) -> List[pathlib.Path]
        """Stored paths
        :param _BaseSourcePaths self: this
        :rtype: list
        :return: list of pathlib.Path
        """
        return self._paths

    def add_include(self, incl):
        # type: (_BaseSourcePaths, str) -> None
        """Add an include
        :param _BaseSourcePaths self: this
        :param str incl: include filter
        """
        if self._include is None:
            self._include = [incl]
        else:
            self._include.append(incl)

    def add_includes(self, includes):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of includes
        :param _BaseSourcePaths self: this
        :param list includes: list of includes
        """
        if not isinstance(includes, list):
            raise ValueError('includes is not of type list')
        if self._include is None:
            self._include = includes
        else:
            self._include.extend(includes)

    def add_exclude(self, excl):
        # type: (_BaseSourcePaths, str) -> None
        """Add an exclude
        :param _BaseSourcePaths self: this
        :param str excl: exclude filter
        """
        if self._exclude is None:
            self._exclude = [excl]
        else:
            self._exclude.append(excl)

    def add_excludes(self, excludes):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of excludes
        :param _BaseSourcePaths self: this
        :param list excludes: list of excludes
        """
        if not isinstance(excludes, list):
            raise ValueError('excludes is not of type list')
        if self._exclude is None:
            self._exclude = excludes
        else:
            self._exclude.extend(excludes)

    def add_path(self, path):
        # type: (_BaseSourcePaths, str) -> None
        """Add a local path
        :param _BaseSourcePaths self: this
        :param str path: path to add
        """
        if isinstance(path, pathlib.Path):
            self._paths.append(path)
        else:
            self._paths.append(pathlib.Path(path))

    def add_paths(self, paths):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of local paths
        :param _BaseSourcePaths self: this
        :param list paths: paths to add
        """
        for path in paths:
            self.add_path(path)

    def _inclusion_check(self, path):
        # type: (_BaseSourcePaths, pathlib.Path) -> bool
        """Check file for inclusion against filters
        :param _BaseSourcePaths self: this
        :param pathlib.Path path: path to check
        :rtype: bool
        :return: if file should be included
        """
        _spath = str(path)
        inc = True
        if self._include is not None:
            inc = any([fnmatch.fnmatch(_spath, x) for x in self._include])
        if inc and self._exclude is not None:
            inc = not any([fnmatch.fnmatch(_spath, x) for x in self._exclude])
        return inc


class LocalSourcePaths(_BaseSourcePaths):
    """Local Source Paths"""
    def files(self):
        # type: (LocalSourcePaths) -> LocalPath
        """Generator for files in paths
        :param LocalSourcePaths self: this
        :rtype: LocalPath
        :return: LocalPath
        """
        for _path in self._paths:
            _ppath = os.path.expandvars(os.path.expanduser(str(_path)))
            _expath = pathlib.Path(_ppath)
            for entry in blobxfer.util.scantree(_ppath):
                _rpath = pathlib.Path(entry.path).relative_to(_ppath)
                if not self._inclusion_check(_rpath):
                    logger.debug(
                        'skipping file {} due to filters'.format(_rpath))
                    continue
                yield LocalPath(parent_path=_expath, relative_path=_rpath)


class LocalDestinationPath(object):
    """Local Destination Path"""
    def __init__(self, path=None):
        # type: (LocalDestinationPath, str) -> None
        """Ctor for LocalDestinationPath
        :param LocalDestinationPath self: this
        :param str path: path
        """
        self._is_dir = None
        if path is not None:
            self.path = path

    @property
    def path(self):
        # type: (LocalDestinationPath) -> pathlib.Path
        """Path property
        :param LocalDestinationPath self: this
        :rtype: pathlib.Path
        :return: local destination path
        """
        return self._path

    @path.setter
    def path(self, value):
        # type: (LocalDestinationPath, str) -> None
        """Path property setter
        :param LocalDestinationPath self: this
        :param str value: value to set path to
        """
        self._path = pathlib.Path(value)

    @property
    def is_dir(self):
        # type: (LocalDestinationPath) -> bool
        """is_dir property
        :param LocalDestinationPath self: this
        :rtype: bool
        :return: if local destination path is a directory
        """
        return self._is_dir

    @is_dir.setter
    def is_dir(self, value):
        # type: (LocalDestinationPath, bool) -> None
        """is_dir property setter
        :param LocalDestinationPath self: this
        :param bool value: value to set is_dir to
        """
        self._is_dir = value

    def ensure_path_exists(self):
        # type: (LocalDestinationPath) -> None
        """Ensure path exists
        :param LocalDestinationPath self: this
        """
        if self._is_dir is None:
            raise RuntimeError('is_dir not set')
        if self._is_dir:
            self._path.mkdir(mode=0o750, parents=True, exist_ok=True)
        else:
            if self._path.exists() and self._path.is_dir():
                raise RuntimeError(
                    ('destination path {} already exists and is a '
                     'directory').format(self._path))
            else:
                # ensure parent path exists and is created
                self._path.parent.mkdir(
                    mode=0o750, parents=True, exist_ok=True)


class DownloadSpecification(object):
    """DownloadSpecification"""
    def __init__(
            self, download_options, skip_on_options, local_destination_path):
        # type: (DownloadSpecification, DownloadOptions, SkipOnOptions,
        #        LocalDestinationPath) -> None
        """Ctor for DownloadSpecification
        :param DownloadSepcification self: this
        :param DownloadOptions download_options: download options
        :param SkipOnOptions skip_on_options: skip on options
        :param LocalDestinationPath local_destination_path: local dest path
        """
        self.options = download_options
        self.skip_on = skip_on_options
        self.destination = local_destination_path
        self.sources = []

    def add_azure_source_path(self, source):
        # type: (DownloadSpecification, AzureSourcePath) -> None
        """Add an Azure Source Path
        :param DownloadSepcification self: this
        :param AzureSourcePath source: Azure source path to add
        """
        self.sources.append(source)


class AzureSourcePath(_BaseSourcePaths):
    """AzureSourcePath"""
    def __init__(self):
        # type: (AzureSourcePath) -> None
        """Ctor for AzureSourcePath
        :param AzureSourcePath self: this
        """
        super(AzureSourcePath, self).__init__()
        self._path_map = {}

    def add_path_with_storage_account(self, remote_path, storage_account):
        # type: (AzureSourcePath, str, str) -> None
        """Add a path with an associated storage account
        :param AzureSourcePath self: this
        :param str remote_path: remote path
        :param str storage_account: storage account to associate with path
        """
        if len(self._path_map) >= 1:
            raise RuntimeError(
                'cannot add multiple remote paths to AzureSourcePath objects')
        rpath = blobxfer.util.normalize_azure_path(remote_path)
        self.add_path(rpath)
        self._path_map[rpath] = storage_account

    def lookup_storage_account(self, remote_path):
        # type: (AzureSourcePath, str) -> str
        """Lookup the storage account associated with the remote path
        :param AzureSourcePath self: this
        :param str remote_path: remote path
        :rtype: str
        :return: storage account associated with path
        """
        return self._path_map[blobxfer.util.normalize_azure_path(remote_path)]

    def files(self, creds, mode):
        if mode == AzureStorageModes.Auto:
            for blob in self._auto_blobs(creds):
                yield blob
        elif mode == AzureStorageModes.Append:
            pass
        elif mode == AzureStorageModes.Block:
            pass
        elif mode == AzureStorageModes.File:
            pass
        elif mode == AzureStorageModes.Page:
            pass
        else:
            raise RuntimeError('unknown Azure Storage Mode: {}'.format(mode))

    def _append_blobs(self):
        for _path in self._paths:
            pass

    def _auto_blobs(self, creds):
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for blob in blobxfer.blob.operations.list_blobs(
                    sa.block_blob_client, cont, dir):
                if blobxfer.crypto.models.EncryptionMetadata.\
                        encryption_metadata_exists(blob.metadata):
                    ed = blobxfer.crypto.models.EncryptionMetadata()
                    ed.convert_from_json(blob.metadata)
                else:
                    ed = None
                yield (_path, blob.name, ed)


class AzureStorageEntity(object):
    def __init__(self):
        self._name = None
        self._size = None
        self._md5 = None
        self._enc = None
        self._vio = None


class AzureDestinationPaths(object):
    def __init__(self):
        pass


class FileDescriptor(object):
    def __init__(self, filepath):
        if filepath == '-':
            self.stdin = True
            self.path = None
        else:
            self.stdin = False
            self.path = pathlib.Path(filepath)
        self.size = None
        self.hmac = None
        self.md5 = None
        self.bytes_xferred = 0


class ReadFileDescriptor(FileDescriptor):
    def __init__(self, filepath):
        super().__init__(filepath)


class WriteFileDescriptor(FileDescriptor):
    def __init__(self, filepath):
        super().__init__(filepath)
