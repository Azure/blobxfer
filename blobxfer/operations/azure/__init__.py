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
import re
# non-stdlib imports
import requests
# local imports
import blobxfer.models
import blobxfer.models.crypto
import blobxfer.models.metadata
import blobxfer.models.options
import blobxfer.operations.azure.blob.append
import blobxfer.operations.azure.blob.block
import blobxfer.operations.azure.blob.page
import blobxfer.operations.azure.file
import blobxfer.util


class StorageCredentials(object):
    """Azure Storage Credentials"""
    def __init__(self, general_options):
        # type: (StorageCredentials, blobxfer.models.options.General) -> None
        """Ctor for StorageCredentials
        :param StorageCredentials self: this
        :param blobxfer.models.options.General: general options
        """
        self._storage_accounts = {}
        self._general_options = general_options

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
        self._storage_accounts[name] = StorageAccount(
            name, key, endpoint,
            self._general_options.concurrency.transfer_threads,
            self._general_options.timeout,
            self._general_options.proxy,
        )

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
    _VALID_BASE64_RE = re.compile(
        '^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|'
        '[A-Za-z0-9+/]{2}==)$')

    def __init__(self, name, key, endpoint, transfer_threads, timeout, proxy):
        # type: (StorageAccount, str, str, str, int,
        #        blobxfer.models.options.Timeout,
        #        blobxfer.models.options.HttpProxy) -> None
        """Ctor for StorageAccount
        :param str name: name of storage account
        :param str key: storage key or sas
        :param str endpoint: endpoint
        :param int transfer_threads: number of transfer threads
        :param blobxfer.models.options.Timeout timeout: timeout
        :param blobxfer.models.options.HttpProxy proxy: proxy
        """
        if blobxfer.util.is_none_or_empty(key):
            raise ValueError(
                ('no authentication credential given for storage '
                 'account: {}').format(name))
        self._endpoint = None
        self._append_blob_client = None
        self._block_blob_client = None
        self._file_client = None
        self._page_blob_client = None
        self.name = name
        self.key = key
        self.endpoint = endpoint
        self.is_sas = StorageAccount._key_is_sas(self.key)
        self.create_containers = self._container_creation_allowed()
        if self.is_sas:
            # normalize sas keys
            if self.key.startswith('?'):
                self.key = self.key[1:]
        else:
            # check if sa shared key is base64
            if StorageAccount._VALID_BASE64_RE.match(self.key) is None:
                raise ValueError(
                    ('specified storage account key is invalid for storage '
                     'account: {}').format(self.name))
        # create requests session for connection pooling
        self.session = requests.Session()
        self.session.mount(
            'https://',
            requests.adapters.HTTPAdapter(
                pool_connections=transfer_threads,
                pool_maxsize=transfer_threads << 2,
                pool_block=False,
            )
        )
        self._create_clients(timeout, proxy)

    @property
    def endpoint(self):
        # type: (StorageAccount) -> str
        """Get endpoint
        :param StorageAccount self: this
        :rtype: str
        :return: endpoint
        """
        return self._endpoint

    @endpoint.setter
    def endpoint(self, value):
        # type: (StorageAccount, str) -> None
        """Set endpoint
        :param StorageAccount self: this
        :param str value: endpoint
        """
        tmp = value.split('.')
        if (len(tmp) <= 1 or not tmp[0].isalnum()):
            raise ValueError('endpoint is invalid: {}'.format(value))
        self._endpoint = value

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

    def _container_creation_allowed(self):
        # # type: (StorageAccount) -> bool
        """Check if container creation is allowed
        :param StorageAccount self: this
        :rtype: bool
        :return: if container creation is allowed
        """
        if self.is_sas:
            # search for account sas "c" resource
            sasparts = self.key.split('&')
            for part in sasparts:
                tmp = part.split('=')
                if tmp[0] == 'srt':
                    if 'c' in tmp[1]:
                        return True
        else:
            # storage account key always allows container creation
            return True
        return False

    def _create_clients(self, timeout, proxy):
        # type: (StorageAccount, blobxfer.models.options.Timeout,
        #        blobxfer.models.options.HttpProxy) -> None
        """Create Azure Storage clients
        :param StorageAccount self: this
        :param blobxfer.models.options.Timeout timeout: timeout
        :param blobxfer.models.options.HttpProxy proxy: proxy
        """
        self._append_blob_client = \
            blobxfer.operations.azure.blob.append.create_client(
                self, timeout, proxy)
        self._block_blob_client = \
            blobxfer.operations.azure.blob.block.create_client(
                self, timeout, proxy)
        self._file_client = blobxfer.operations.azure.file.create_client(
            self, timeout, proxy)
        self._page_blob_client = \
            blobxfer.operations.azure.blob.page.create_client(
                self, timeout, proxy)

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

    def files(self, creds, options):
        # type: (SourcePath, StorageCredentials,
        #        blobxfer.models.options.Download) -> StorageEntity
        """Generator of Azure remote files or blobs
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param blobxfer.models.options.Download options: download options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        if options.mode == blobxfer.models.azure.StorageModes.File:
            for file in self._populate_from_list_files(creds, options):
                yield file
        else:
            for blob in self._populate_from_list_blobs(creds, options):
                yield blob

    def _convert_to_storage_entity_with_encryption_metadata(
            self, options, store_raw_metadata, sa, entity, vio, is_file,
            container, dir, file_snapshot):
        # type: (SourcePath, StorageCredentials, any, bool, StorageAccount,
        #        any, blobxfer.models.metadata.VectoredStripe, bool, str,
        #        str) -> StorageEntity
        """Convert entity into StorageEntity with encryption metadata if avail
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param object options: download or synccopy options
        :param bool store_raw_metadata: store raw metadata
        :param StorageAccount sa: storage account
        :param object entity: Storage File or Blob object
        :param blobxfer.models.metadata.VectoredStripe vio: Vectored stripe
        :param bool is_file: is a file object
        :param str container: container
        :param str dir: Azure File directory structure
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        if (not store_raw_metadata and
                blobxfer.models.crypto.EncryptionMetadata.
                encryption_metadata_exists(entity.metadata)):
            ed = blobxfer.models.crypto.EncryptionMetadata()
            ed.convert_from_json(
                entity.metadata, entity.name, options.rsa_private_key)
        else:
            ed = None
        ase = blobxfer.models.azure.StorageEntity(container, ed)
        if is_file:
            ase.populate_from_file(
                sa, entity, dir, vio=vio,
                store_raw_metadata=store_raw_metadata, snapshot=file_snapshot)
        else:
            ase.populate_from_blob(
                sa, entity, vio=vio, store_raw_metadata=store_raw_metadata)
        return ase

    def _handle_vectored_io_stripe(
            self, creds, options, store_raw_metadata, sa, entity, is_file,
            container, dir=None, file_snapshot=None):
        # type: (SourcePath, StorageCredentials, any, bool, StorageAccount,
        #        any, bool, str, str) -> StorageEntity
        """Handle Vectored IO stripe entries
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param object options: download or synccopy options
        :param bool store_raw_metadata: store raw metadata
        :param StorageAccount sa: storage account
        :param object entity: Storage File or Blob object
        :param bool is_file: is a file object
        :param str container: container
        :param str dir: Azure File directory structure
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        vio = blobxfer.models.metadata.vectored_io_from_metadata(
            entity.metadata)
        if not isinstance(vio, blobxfer.models.metadata.VectoredStripe):
            ase = self._convert_to_storage_entity_with_encryption_metadata(
                options, store_raw_metadata, sa, entity, None, is_file,
                container, dir, file_snapshot)
            yield ase
            return
        # if this slice is not the first, ignore. the reason for this is
        # 1. Ensures direct get on a slice does nothing unless the
        # zero-th blob is retrieved/accessed (eliminates partial data
        # download), which will reconstruct all of the stripes via next
        # pointers
        # 2. Data is not retrieved multiple times for the same slice without
        # having to maintain a fetched map
        if vio.slice_id != 0:
            yield None
            return
        # yield this entity
        ase = self._convert_to_storage_entity_with_encryption_metadata(
            options, store_raw_metadata, sa, entity, vio, is_file, container,
            dir, file_snapshot)
        yield ase
        # iterate all slices
        while vio.next is not None:
            # follow next pointer
            sa = creds.get_storage_account(vio.next.storage_account_name)
            if is_file:
                entity = blobxfer.operations.azure.file.get_file_properties(
                    sa.file_client, vio.next.container, vio.next.name,
                    snapshot=file_snapshot)
                _, dir = blobxfer.util.explode_azure_path(vio.next.name)
            else:
                entity = blobxfer.operations.azure.blob.get_blob_properties(
                    sa.block_blob_client, vio.next.container, vio.next.name,
                    ase.mode)
            vio = blobxfer.models.metadata.vectored_io_from_metadata(
                entity.metadata)
            # yield next
            ase = self._convert_to_storage_entity_with_encryption_metadata(
                options, store_raw_metadata, sa, entity, vio, is_file,
                container, dir, file_snapshot)
            yield ase

    def _populate_from_list_files(self, creds, options):
        # type: (SourcePath, StorageCredentials, any) -> StorageEntity
        """Internal generator for Azure remote files
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param object options: download or synccopy options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        store_raw_metadata = isinstance(
            options, blobxfer.models.options.SyncCopy)
        for _path in self._paths:
            rpath = str(_path)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            snapshot = None
            if dir is not None:
                # parse out snapshot if part of url
                a, b, snapshot = \
                    blobxfer.operations.azure.file.parse_file_path(dir)
                # check if "dir" is a file or a vdir
                chk = blobxfer.operations.azure.file.check_if_single_file(
                    sa.file_client, cont, dir)
                if chk[0]:
                    dir = a
                else:
                    if blobxfer.util.is_not_empty(a):
                        dir = '/'.join((a, b))
                    else:
                        dir = b
            if snapshot is None:
                _, cont, snapshot = \
                    blobxfer.operations.azure.file.parse_file_path(cont)
            for file in blobxfer.operations.azure.file.list_files(
                    sa.file_client, cont, dir, options.recursive,
                    snapshot=snapshot):
                if not self._inclusion_check(file.name):
                    continue
                for ase in self._handle_vectored_io_stripe(
                        creds, options, store_raw_metadata, sa, file, True,
                        cont, dir=None, file_snapshot=snapshot):
                    if ase is None:
                        continue
                    yield ase

    def _populate_from_list_blobs(self, creds, options):
        # type: (SourcePath, StorageCredentials, any) -> StorageEntity
        """Internal generator for Azure remote blobs
        :param SourcePath self: this
        :param StorageCredentials creds: storage creds
        :param object options: download or synccopy options
        :rtype: StorageEntity
        :return: Azure storage entity object
        """
        is_synccopy = isinstance(options, blobxfer.models.options.SyncCopy)
        for _path in self._paths:
            rpath = str(_path)
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            sa = creds.get_storage_account(self.lookup_storage_account(rpath))
            for blob in blobxfer.operations.azure.blob.list_blobs(
                    sa.block_blob_client, cont, dir, options.mode,
                    options.recursive):
                if not self._inclusion_check(blob.name):
                    continue
                for ase in self._handle_vectored_io_stripe(
                        creds, options, is_synccopy, sa, blob,
                        False, cont):
                    if ase is None:
                        continue
                    yield ase


class DestinationPath(blobxfer.models._BaseSourcePaths):
    """Azure Destination Path"""
    def __init__(self):
        # type: (SourcePath) -> None
        """Ctor for SourcePath
        :param SourcePath self: this
        """
        super(DestinationPath, self).__init__()
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
