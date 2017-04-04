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
from azure.storage.blob.models import _BlobTypes as BlobTypes
# local imports
import blobxfer.models
import blobxfer.operations.azure.blob
import blobxfer.operations.azure.blob.append
import blobxfer.operations.azure.blob.block
import blobxfer.operations.azure.blob.page
import blobxfer.operations.azure.file


# enums
class StorageModes(enum.Enum):
    Auto = 10
    Append = 20
    Block = 30
    File = 40
    Page = 50


class StorageCredentials(object):
    """Azure Storage Credentials"""
    def __init__(self):
        # type: (StorageCredentials) -> None
        """Ctor for StorageCredentials"""
        self._storage_accounts = {}

    def add_storage_account(self, name, key, endpoint):
        # type: (StorageCredentials, str, str, str) -> None
        """Add a storage account
        :param StorageCredentials self: this
        :param str name: name of storage account to store
        :param str key: storage key or sas
        :param str endpoint: endpoint
        """
        if name in self._storage_accounts:
            raise ValueError(
                '{} already exists in storage accounts'.format(name))
        self._storage_accounts[name] = StorageAccount(name, key, endpoint)

    def get_storage_account(self, name):
        # type: (StorageCredentials, str) -> StorageAccount
        """Get storage account details
        :param StorageCredentials self: this
        :param str name: name of storage account to retrieve
        :rtype: StorageAccount
        :return: storage account details
        """
        return self._storage_accounts[name]


class StorageAccount(object):
    """Azure Storage Account"""
    def __init__(self, name, key, endpoint):
        # type: (StorageAccount, str, str, str) -> None
        """Ctor for StorageAccount
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
        # type: (StorageAccount) -> None
        """Create Azure Storage clients
        :param StorageAccount self: this
        """
        self._append_blob_client = \
            blobxfer.operations.azure.blob.append.create_client(self)
        self._block_blob_client = \
            blobxfer.operations.azure.blob.block.create_client(self)
        self._file_client = blobxfer.operations.azure.file.create_client(self)
        self._page_blob_client = \
            blobxfer.operations.azure.blob.page.create_client(self)

    @property
    def append_blob_client(self):
        # type: (StorageAccount) -> azure.storage.blob.AppendBlobService
        """Get append blob client
        :param StorageAccount self: this
        :rtype: azure.storage.blob.AppendBlobService
        :return: append blob client
        """
        return self._append_blob_client

    @property
    def block_blob_client(self):
        # type: (StorageAccount) -> azure.storage.blob.BlockBlobService
        """Get block blob client
        :param StorageAccount self: this
        :rtype: azure.storage.blob.BlockBlobService
        :return: block blob client
        """
        return self._block_blob_client

    @property
    def file_client(self):
        # type: (StorageAccount) -> azure.storage.file.FileService
        """Get file client
        :param StorageAccount self: this
        :rtype: azure.storage.file.FileService
        :return: file client
        """
        return self._file_client

    @property
    def page_blob_client(self):
        # type: (StorageAccount) -> azure.storage.blob.PageBlobService
        """Get page blob client
        :param StorageAccount self: this
        :rtype: azure.storage.blob.PageBlobService
        :return: page blob client
        """
        return self._page_blob_client


class StorageEntity(object):
    """Azure Storage Entity"""
    def __init__(self, container, ed=None):
        # type: (StorageEntity, str
        #        blobxfer.models.crypto.EncryptionMetadata) -> None
        """Ctor for StorageEntity
        :param StorageEntity self: this
        :param str container: container name
        :param blobxfer.models.crypto.EncryptionMetadata ed:
            encryption metadata
        """
        self._client = None
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
    def client(self):
        # type: (StorageEntity) -> object
        """Associated storage client
        :param StorageEntity self: this
        :rtype: object
        :return: associated storage client
        """
        return self._client

    @property
    def container(self):
        # type: (StorageEntity) -> str
        """Container name
        :param StorageEntity self: this
        :rtype: str
        :return: name of container or file share
        """
        return self._container

    @property
    def name(self):
        # type: (StorageEntity) -> str
        """Entity name
        :param StorageEntity self: this
        :rtype: str
        :return: name of entity
        """
        return self._name

    @property
    def lmt(self):
        # type: (StorageEntity) -> datetime.datetime
        """Entity last modified time
        :param StorageEntity self: this
        :rtype: datetime.datetime
        :return: LMT of entity
        """
        return self._lmt

    @property
    def size(self):
        # type: (StorageEntity) -> int
        """Entity size
        :param StorageEntity self: this
        :rtype: int
        :return: size of entity
        """
        return self._size

    @property
    def snapshot(self):
        # type: (StorageEntity) -> str
        """Entity snapshot
        :param StorageEntity self: this
        :rtype: str
        :return: snapshot of entity
        """
        return self._snapshot

    @property
    def md5(self):
        # type: (StorageEntity) -> str
        """Base64-encoded MD5
        :param StorageEntity self: this
        :rtype: str
        :return: md5 of entity
        """
        return self._md5

    @property
    def mode(self):
        # type: (StorageEntity) -> blobxfer.models.azure.StorageModes
        """Entity mode (type)
        :param StorageEntity self: this
        :rtype: blobxfer.models.azure.StorageModes
        :return: type of entity
        """
        return self._mode

    @property
    def is_encrypted(self):
        # type: (StorageEntity) -> bool
        """If data is encrypted
        :param StorageEntity self: this
        :rtype: bool
        :return: if encryption metadata is present
        """
        return self._encryption is not None

    @property
    def encryption_metadata(self):
        # type: (StorageEntity) ->
        #        blobxfer.models.crypto.EncryptionMetadata
        """Entity metadata (type)
        :param StorageEntity self: this
        :rtype: blobxfer.models.crypto.EncryptionMetadata
        :return: encryption metadata of entity
        """
        return self._encryption

    def populate_from_blob(self, sa, blob):
        # type: (StorageEntity, blobxfer.models.azure.StorageAccount,
        #        azure.storage.blob.models.Blob) -> None
        """Populate properties from Blob
        :param StorageEntity self: this
        :param blobxfer.models.azure.StorageAccount sa: storage account
        :param azure.storage.blob.models.Blob blob: blob to populate from
        """
        self._name = blob.name
        self._snapshot = blob.snapshot
        self._lmt = blob.properties.last_modified
        self._size = blob.properties.content_length
        self._md5 = blob.properties.content_settings.content_md5
        if blob.properties.blob_type == BlobTypes.AppendBlob:
            self._mode = StorageModes.Append
            self._client = sa.append_blob_client
        elif blob.properties.blob_type == BlobTypes.BlockBlob:
            self._mode = StorageModes.Block
            self._client = sa.block_blob_client
        elif blob.properties.blob_type == BlobTypes.PageBlob:
            self._mode = StorageModes.Page
            self._client = sa.page_blob_client

    def populate_from_file(self, sa, file):
        # type: (StorageEntity, blobxfer.models.azure.StorageAccount,
        #        azure.storage.file.models.File) -> None
        """Populate properties from File
        :param StorageEntity self: this
        :param blobxfer.models.azure.StorageAccount sa: storage account
        :param azure.storage.file.models.File file: file to populate from
        """
        self._name = file.name
        self._snapshot = None
        self._lmt = file.properties.last_modified
        self._size = file.properties.content_length
        self._md5 = file.properties.content_settings.content_md5
        self._mode = StorageModes.File
        self._client = sa.file_client


class SourcePath(blobxfer.models._BaseSourcePaths):
    """Azure Source Path"""
    def __init__(self):
        # type: (SourcePath) -> None
        """Ctor for SourcePath
        :param SourcePath self: this
        """
        super(SourcePath, self).__init__()
        self._path_map = {}

    def add_path_with_storage_account(self, remote_path, storage_account):
        # type: (SourcePath, str, str) -> None
        """Add a path with an associated storage account
        :param SourcePath self: this
        :param str remote_path: remote path
        :param str storage_account: storage account to associate with path
        """
        if len(self._path_map) >= 1:
            raise RuntimeError(
                'cannot add multiple remote paths to SourcePath objects')
        rpath = blobxfer.util.normalize_azure_path(remote_path)
        self.add_path(rpath)
        self._path_map[rpath] = storage_account

    def lookup_storage_account(self, remote_path):
        # type: (SourcePath, str) -> str
        """Lookup the storage account associated with the remote path
        :param SourcePath self: this
        :param str remote_path: remote path
        :rtype: str
        :return: storage account associated with path
        """
        return self._path_map[blobxfer.util.normalize_azure_path(remote_path)]

    def files(self, creds, options, general_options):
        # type: (SourcePath, StorageCredentials,
        #        blobxfer.models.options.Download,
        #        blobxfer.models.options.General) -> StorageEntity
        """Generator of Azure remote files or blobs
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param blobxfer.models.options.Download options: download options
        :param blobxfer.models.options.General general_options: general options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        if options.mode == blobxfer.models.azure.StorageModes.File:
            for file in self._populate_from_list_files(
                    creds, options, general_options):
                yield file
        else:
            for blob in self._populate_from_list_blobs(
                    creds, options, general_options):
                yield blob

    def _populate_from_list_files(self, creds, options, general_options):
        # type: (SourcePath, StorageCredentials,
        #        blobxfer.models.options.Download,
        #        blobxfer.models.options.General) -> StorageEntity
        """Internal generator for Azure remote files
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param blobxfer.models.options.Download options: download options
        :param blobxfer.models.options.General general_options: general options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for file in blobxfer.operations.azure.file.list_files(
                    sa.file_client, cont, dir, general_options.timeout_sec):
                if blobxfer.models.crypto.EncryptionMetadata.\
                        encryption_metadata_exists(file.metadata):
                    ed = blobxfer.models.crypto.EncryptionMetadata()
                    ed.convert_from_json(
                        file.metadata, file.name, options.rsa_private_key)
                else:
                    ed = None
                ase = blobxfer.models.azure.StorageEntity(cont, ed)
                ase.populate_from_file(sa, file)
                yield ase

    def _populate_from_list_blobs(self, creds, options, general_options):
        # type: (SourcePath, StorageCredentials,
        #        blobxfer.models.options.Download,
        #        blobxfer.models.options.General) -> StorageEntity
        """Internal generator for Azure remote blobs
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param blobxfer.models.options.Download options: download options
        :param blobxfer.models.options.General general_options: general options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for blob in blobxfer.operations.azure.blob.list_blobs(
                    sa.block_blob_client, cont, dir, options.mode,
                    general_options.timeout_sec):
                if blobxfer.models.crypto.EncryptionMetadata.\
                        encryption_metadata_exists(blob.metadata):
                    ed = blobxfer.models.crypto.EncryptionMetadata()
                    ed.convert_from_json(
                        blob.metadata, blob.name, options.rsa_private_key)
                else:
                    ed = None
                ase = blobxfer.models.azure.StorageEntity(cont, ed)
                ase.populate_from_blob(sa, blob)
                yield ase
