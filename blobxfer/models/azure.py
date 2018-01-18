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
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
from azure.storage.blob.models import _BlobTypes as BlobTypes
# local imports
import blobxfer.models.metadata


# enums
class StorageModes(enum.Enum):
    Auto = 10
    Append = 20
    Block = 30
    File = 40
    Page = 50


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
        self._create_containers = None
        self._client = None
        self._container = container
        self._name = None
        self._mode = None
        self._lmt = None
        self._size = None
        self._snapshot = None
        self._md5 = None
        self._encryption = ed
        self._from_local = False
        self._append_create = True
        self._vio = None
        self._fileattr = None
        self._raw_metadata = None
        self._access_tier = None
        self.replica_targets = None

    @property
    def create_containers(self):
        # type: (StorageEntity) -> bool
        """Create containers
        :param StorageEntity self: this
        :rtype: bool
        :return: create containers
        """
        return self._create_containers

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
    def path(self):
        # type: (StorageEntity) -> str
        """Entity path
        :param StorageEntity self: this
        :rtype: str
        :return: remote path of entity
        """
        return '{}/{}'.format(self._container, self._name)

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

    @size.setter
    def size(self, value):
        # type: (StorageEntity, int) -> None
        """Set entity size
        :param StorageEntity self: this
        :param int value: value
        """
        self._size = value

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
    def from_local(self):
        # type: (StorageEntity) -> bool
        """If entity was created from a local file (no remote exists)
        :param StorageEntity self: this
        :rtype: bool
        :return: if entity is from local (no remote exists)
        """
        return self._from_local

    @property
    def append_create(self):
        # type: (StorageEntity) -> bool
        """If append blob should be created
        :param StorageEntity self: this
        :rtype: bool
        :return: if append blob should be created
        """
        return self._append_create

    @append_create.setter
    def append_create(self, value):
        # type: (StorageEntity, bool) -> None
        """Set append create option
        :param StorageEntity self: this
        :param bool value: value to set
        """
        self._append_create = value

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
        """Get encryption metadata
        :param StorageEntity self: this
        :rtype: blobxfer.models.crypto.EncryptionMetadata
        :return: encryption metadata of entity
        """
        return self._encryption

    @encryption_metadata.setter
    def encryption_metadata(self, value):
        # type: (StorageEntity,
        #        blobxfer.models.crypto.EncryptionMetadata) -> None
        """Set encryption metadata
        :param StorageEntity self: this
        :param blobxfer.models.crypto.EncryptionMetadata value: value
        """
        self._encryption = value

    @property
    def file_attributes(self):
        # type: (StorageEntity) -> object
        """Return file attributes collection
        :param StorageEntity self: this
        :rtype: blobxfer.models.metadata.PosixFileAttr or
            blobxfer.models.metadata.WindowsFileAttr or None
        :return: file attributes
        """
        return self._fileattr

    @property
    def vectored_io(self):
        # type: (StorageEntity) -> object
        """Return vectored io metadata, currently stripe only
        :param StorageEntity self: this
        :rtype: blobxfer.models.metadata.VectoredStripe or None
        :return: vectored io metadata
        """
        return self._vio

    @property
    def raw_metadata(self):
        # type: (StorageEntity) -> dict
        """Return raw metadata for synccopy sources
        :param StorageEntity self: this
        :rtype: dict
        :return: raw metadata
        """
        return self._raw_metadata

    @property
    def access_tier(self):
        # type: (StorageEntity) -> str
        """Return access tier for blob
        :param StorageEntity self: this
        :rtype: str
        :return: access tier
        """
        return self._access_tier

    @access_tier.setter
    def access_tier(self, value):
        # type: (StorageEntity, str) -> None
        """Set access tier
        :param StorageEntity self: this
        :param str value: value
        """
        self._access_tier = value

    def populate_from_blob(self, sa, blob, vio=None, store_raw_metadata=False):
        # type: (StorageEntity, blobxfer.operations.azure.StorageAccount,
        #        azure.storage.blob.models.Blob) -> None
        """Populate properties from Blob
        :param StorageEntity self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
        :param azure.storage.blob.models.Blob blob: blob to populate from
        :param blobxfer.models.metadata.VectoredStripe vio: Vectored stripe
        :param bool store_raw_metadata: store raw metadata
        """
        if store_raw_metadata:
            self._raw_metadata = blob.metadata
        else:
            self._fileattr = blobxfer.models.metadata.fileattr_from_metadata(
                blob.metadata)
        self._vio = vio
        self._create_containers = sa.create_containers
        self._name = blob.name
        self._snapshot = blob.snapshot
        self._lmt = blob.properties.last_modified
        self._size = blob.properties.content_length
        self._md5 = blob.properties.content_settings.content_md5
        if blob.properties.blob_type == BlobTypes.AppendBlob:
            self._mode = StorageModes.Append
            self._client = sa.append_blob_client
        elif blob.properties.blob_type == BlobTypes.BlockBlob:
            self._access_tier = blob.properties.blob_tier
            self._mode = StorageModes.Block
            self._client = sa.block_blob_client
        elif blob.properties.blob_type == BlobTypes.PageBlob:
            self._mode = StorageModes.Page
            self._client = sa.page_blob_client

    def populate_from_file(
            self, sa, file, path, vio=None, store_raw_metadata=False,
            snapshot=None):
        # type: (StorageEntity, blobxfer.operations.azure.StorageAccount,
        #        azure.storage.file.models.File, str,
        #        blobxfer.models.metadata.VectoredStripe, bool, str) -> None
        """Populate properties from File
        :param StorageEntity self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
        :param azure.storage.file.models.File file: file to populate from
        :param str path: full path to file
        :param blobxfer.models.metadata.VectoredStripe vio: Vectored stripe
        :param bool store_raw_metadata: store raw metadata
        :param str snapshot: snapshot
        """
        if store_raw_metadata:
            self._raw_metadata = file.metadata
        else:
            self._fileattr = blobxfer.models.metadata.fileattr_from_metadata(
                file.metadata)
        self._vio = vio
        self._create_containers = sa.create_containers
        if path is not None:
            self._name = str(pathlib.Path(path) / file.name)
        else:
            self._name = file.name
        self._snapshot = snapshot
        self._lmt = file.properties.last_modified
        self._size = file.properties.content_length
        self._md5 = file.properties.content_settings.content_md5
        self._mode = StorageModes.File
        self._client = sa.file_client

    def populate_from_local(self, sa, container, path, mode):
        # type: (StorageEntity, blobxfer.operations.azure.StorageAccount
        #        str, str, blobxfer.models.azure.StorageModes) -> None
        """Populate properties from local
        :param StorageEntity self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
        :param str container: container
        :param str path: full path to file
        :param blobxfer.models.azure.StorageModes mode: storage mode
        """
        self._create_containers = sa.create_containers
        self._container = container
        self._name = path
        self._mode = mode
        self._from_local = True
        if mode == StorageModes.Append:
            self._client = sa.append_blob_client
        elif mode == StorageModes.Block:
            self._client = sa.block_blob_client
        elif mode == StorageModes.File:
            self._client = sa.file_client
        elif mode == StorageModes.Page:
            self._client = sa.page_blob_client
        elif mode == StorageModes.Auto:
            name = self.name.lower()
            if name.endswith('.vhd') or name.endswith('.vhdx'):
                self._client = sa.page_blob_client
                self._mode = StorageModes.Page
            else:
                self._client = sa.block_blob_client
                self._mode = StorageModes.Block
