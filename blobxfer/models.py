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
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# local imports
from .api import (
    create_append_blob_client,
    create_block_blob_client,
    create_file_client,
    create_page_blob_client,
)
from azure.storage.blob.models import _BlobTypes as BlobTypes
import blobxfer.blob.operations
import blobxfer.file.operations
import blobxfer.crypto.models
import blobxfer.md5
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


# enums
class AzureStorageModes(enum.Enum):
    Auto = 10
    Append = 20
    Block = 30
    File = 40
    Page = 50


# named tuples
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


class ConcurrencyOptions(object):
    """Concurrency Options"""
    def __init__(self, crypto_processes, md5_processes, transfer_threads):
        """Ctor for Concurrency Options
        :param ConcurrencyOptions self: this
        :param int crypto_processes: number of crypto procs
        :param int md5_processes: number of md5 procs
        :param int transfer_threads: number of transfer threads
        """
        self.crypto_processes = crypto_processes
        self.md5_processes = md5_processes
        self.transfer_threads = transfer_threads
        if self.crypto_processes is None or self.crypto_processes < 1:
            self.crypto_processes = 1
        if self.md5_processes is None or self.md5_processes < 1:
            self.md5_processes = 1
        if self.transfer_threads is None or self.transfer_threads < 1:
            self.transfer_threads = 1


class GeneralOptions(object):
    """General Options"""
    def __init__(
            self, concurrency, progress_bar=True, timeout_sec=None,
            verbose=False):
        """Ctor for General Options
        :param GeneralOptions self: this
        :param ConcurrencyOptions concurrency: concurrency options
        :param bool progress_bar: progress bar
        :param int timeout_sec: timeout in seconds
        :param bool verbose: verbose output
        """
        if concurrency is None:
            raise ValueError('concurrency option is unspecified')
        self.concurrency = concurrency
        self.progress_bar = progress_bar
        self.timeout_sec = timeout_sec
        self.verbose = verbose


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

    def files(self, creds, options, general_options):
        # type: (AzureSourcePath, AzureStorageCredentials, DownloadOptions,
        #        GeneralOptions) -> AzureStorageEntity
        """Generator of Azure remote files or blobs
        :param AzureSourcePath self: this
        :param AzureStorageCredentials creds: storage creds
        :param DownloadOptions options: download options
        :param GeneralOptions general_options: general options
        :rtype: AzureStorageEntity
        :return: Azure storage entity object
        """
        if options.mode == AzureStorageModes.File:
            for file in self._populate_from_list_files(
                    creds, options, general_options):
                yield file
        else:
            for blob in self._populate_from_list_blobs(
                    creds, options, general_options):
                yield blob

    def _populate_from_list_files(self, creds, options, general_options):
        # type: (AzureSourcePath, AzureStorageCredentials, DownloadOptions,
        #        GeneralOptions) -> AzureStorageEntity
        """Internal generator for Azure remote files
        :param AzureSourcePath self: this
        :param AzureStorageCredentials creds: storage creds
        :param DownloadOptions options: download options
        :param GeneralOptions general_options: general options
        :rtype: AzureStorageEntity
        :return: Azure storage entity object
        """
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for file in blobxfer.file.operations.list_files(
                    sa.file_client, cont, dir, general_options.timeout_sec):
                if blobxfer.crypto.models.EncryptionMetadata.\
                        encryption_metadata_exists(file.metadata):
                    ed = blobxfer.crypto.models.EncryptionMetadata()
                    ed.convert_from_json(
                        file.metadata, file.name, options.rsa_private_key)
                else:
                    ed = None
                ase = AzureStorageEntity(cont, ed)
                ase.populate_from_file(file)
                yield ase

    def _populate_from_list_blobs(self, creds, options, general_options):
        # type: (AzureSourcePath, AzureStorageCredentials, DownloadOptions,
        #        GeneralOptions) -> AzureStorageEntity
        """Internal generator for Azure remote blobs
        :param AzureSourcePath self: this
        :param AzureStorageCredentials creds: storage creds
        :param DownloadOptions options: download options
        :param GeneralOptions general_options: general options
        :rtype: AzureStorageEntity
        :return: Azure storage entity object
        """
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for blob in blobxfer.blob.operations.list_blobs(
                    sa.block_blob_client, cont, dir, options.mode,
                    general_options.timeout_sec):
                if blobxfer.crypto.models.EncryptionMetadata.\
                        encryption_metadata_exists(blob.metadata):
                    ed = blobxfer.crypto.models.EncryptionMetadata()
                    ed.convert_from_json(
                        blob.metadata, blob.name, options.rsa_private_key)
                else:
                    ed = None
                ase = AzureStorageEntity(cont, ed)
                ase.populate_from_blob(blob)
                yield ase


class AzureStorageEntity(object):
    """Azure Storage Entity"""
    def __init__(self, container, ed=None):
        # type: (AzureStorageEntity, str
        #        blobxfer.crypto.models.EncryptionMetadata) -> None
        """Ctor for AzureStorageEntity
        :param AzureStorageEntity self: this
        :param str container: container name
        :param blobxfer.crypto.models.EncryptionMetadata ed:
            encryption metadata
        """
        self._container = container
        self._name = None
        self._mode = None
        self._lmt = None
        self._size = None
        self._snapshot = None
        self._md5 = None
        self._encryption = ed
        self._vio = None
        self.download = None

    @property
    def container(self):
        # type: (AzureStorageEntity) -> str
        """Container name
        :param AzureStorageEntity self: this
        :rtype: str
        :return: name of container or file share
        """
        return self._container

    @property
    def name(self):
        # type: (AzureStorageEntity) -> str
        """Entity name
        :param AzureStorageEntity self: this
        :rtype: str
        :return: name of entity
        """
        return self._name

    @property
    def lmt(self):
        # type: (AzureStorageEntity) -> datetime.datetime
        """Entity last modified time
        :param AzureStorageEntity self: this
        :rtype: datetime.datetime
        :return: LMT of entity
        """
        return self._lmt

    @property
    def size(self):
        # type: (AzureStorageEntity) -> int
        """Entity size
        :param AzureStorageEntity self: this
        :rtype: int
        :return: size of entity
        """
        return self._size

    @property
    def md5(self):
        # type: (AzureStorageEntity) -> str
        """Base64-encoded MD5
        :param AzureStorageEntity self: this
        :rtype: str
        :return: md5 of entity
        """
        return self._md5

    @property
    def mode(self):
        # type: (AzureStorageEntity) -> AzureStorageModes
        """Entity mode (type)
        :param AzureStorageEntity self: this
        :rtype: AzureStorageModes
        :return: type of entity
        """
        return self._mode

    @property
    def encryption_metadata(self):
        # type: (AzureStorageEntity) ->
        #        blobxfer.crypto.models.EncryptionMetadata
        """Entity mode (type)
        :param AzureStorageEntity self: this
        :rtype: blobxfer.crypto.models.EncryptionMetadata
        :return: encryption metadata of entity
        """
        return self._encryption

    def populate_from_blob(self, blob):
        # type: (AzureStorageEntity, azure.storage.blob.models.Blob) -> None
        """Populate properties from Blob
        :param AzureStorageEntity self: this
        :param azure.storage.blob.models.Blob blob: blob to populate from
        """
        self._name = blob.name
        self._snapshot = blob.snapshot
        self._lmt = blob.properties.last_modified
        self._size = blob.properties.content_length
        self._md5 = blob.properties.content_settings.content_md5
        if blob.properties.blob_type == BlobTypes.AppendBlob:
            self._mode = AzureStorageModes.Append
        elif blob.properties.blob_type == BlobTypes.BlockBlob:
            self._mode = AzureStorageModes.Block
        elif blob.properties.blob_type == BlobTypes.PageBlob:
            self._mode = AzureStorageModes.Page

    def populate_from_file(self, file):
        # type: (AzureStorageEntity, azure.storage.file.models.File) -> None
        """Populate properties from File
        :param AzureStorageEntity self: this
        :param azure.storage.file.models.File file: file to populate from
        """
        self._name = file.name
        self._lmt = file.properties.last_modified
        self._size = file.properties.content_length
        self._md5 = file.properties.content_settings.content_md5
        self._mode = AzureStorageModes.File

    def prepare_for_download(self, lpath, options):
        # type: (AzureStorageEntity, pathlib.Path, DownloadOptions) -> None
        """Prepare entity for download
        :param AzureStorageEntity self: this
        :param pathlib.Path lpath: local path
        :param DownloadOptions options: download options
        """
        if self._encryption is not None:
            hmac = self._encryption.initialize_hmac()
        else:
            hmac = None
        if hmac is None and options.check_file_md5:
            md5 = blobxfer.md5.new_md5_hasher()
        else:
            md5 = None
        self.download = DownloadDescriptor(lpath, hmac, md5)
        self.download.allocate_disk_space(
            self._size, self._encryption is not None)


class DownloadDescriptor(object):
    """DownloadDescriptor"""
    def __init__(self, lpath, hmac, md5):
        # type: (DownloadDescriptior, pathlib.Path, hmac.HMAC, md5.MD5) -> None
        """Ctor for Download Descriptor
        :param DownloadDescriptor self: this
        :param pathlib.Path lpath: local path
        :param hmac.HMAC hmac: hmac
        :param md5.MD5 md5: md5
        """
        self.final_path = lpath
        # create path holding the temporary file to download to
        _tmp = list(lpath.parts[:-1])
        _tmp.append(lpath.name + '.bxtmp')
        self.local_path = pathlib.Path(*_tmp)
        self.hmac = hmac
        self.md5 = md5
        self.current_position = 0

    def allocate_disk_space(self, size, encryption):
        # type: (DownloadDescriptor, int, bool) -> None
        """Perform file allocation (possibly sparse), if encrypted this may
        be an underallocation
        :param DownloadDescriptor self: this
        :param int size: size
        :param bool encryption: encryption enabled
        """
        # compute size
        if size > 0:
            if encryption:
                allocatesize = size - \
                    blobxfer.crypto.models._AES256_BLOCKSIZE_BYTES
            else:
                allocatesize = size
            if allocatesize < 0:
                allocatesize = 0
        else:
            allocatesize = 0
        # create parent path
        self.local_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        # allocate file
        with self.local_path.open('wb') as fd:
            if allocatesize > 0:
                try:
                    os.posix_fallocate(fd.fileno(), 0, allocatesize)
                except AttributeError:
                    fd.seek(allocatesize - 1)
                    fd.write(b'\0')


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
