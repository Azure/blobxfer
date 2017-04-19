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
        # type: (StorageEntity, blobxfer.operations.azure.StorageAccount,
        #        azure.storage.blob.models.Blob) -> None
        """Populate properties from Blob
        :param StorageEntity self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
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
        # type: (StorageEntity, blobxfer.operations.azure.StorageAccount,
        #        azure.storage.file.models.File) -> None
        """Populate properties from File
        :param StorageEntity self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
        :param azure.storage.file.models.File file: file to populate from
        """
        self._name = file.name
        self._snapshot = None
        self._lmt = file.properties.last_modified
        self._size = file.properties.content_length
        self._md5 = file.properties.content_settings.content_md5
        self._mode = StorageModes.File
        self._client = sa.file_client
