# coding=utf-8
"""Tests for models azure"""

# stdlib imports
import unittest.mock as mock
# non-stdlib imports
import azure.storage.blob
import azure.storage.file
# local imports
import blobxfer.models.crypto
# module under test
import blobxfer.models.azure as azmodels


def test_azurestorageentity():
    ase = azmodels.StorageEntity('cont')
    assert ase.container == 'cont'
    assert ase.encryption_metadata is None

    blob = mock.MagicMock()
    blob.name = 'name'
    blob.snapshot = None
    blob.properties = mock.MagicMock()
    blob.properties.last_modified = 'lmt'
    blob.properties.content_length = 123
    blob.properties.content_settings = mock.MagicMock()
    blob.properties.content_settings.content_md5 = 'abc'
    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.BlockBlob
    blob.properties.blob_tier = 'Cool'
    ase.populate_from_blob(mock.MagicMock(), blob)

    assert ase.can_create_containers is not None
    assert ase.client is not None
    assert ase.name == 'name'
    assert ase.lmt == 'lmt'
    assert ase.size == 123
    assert ase.md5 == 'abc'
    assert not ase.from_local
    assert ase.append_create
    assert ase.encryption_metadata is None
    assert ase.raw_metadata is None
    assert ase.snapshot is None
    assert ase.access_tier == 'Cool'
    assert ase.mode == azmodels.StorageModes.Block

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.AppendBlob
    blob.metadata = '{}'
    ase.populate_from_blob(mock.MagicMock(), blob, store_raw_metadata=True)
    assert ase.mode == azmodels.StorageModes.Append
    assert ase.raw_metadata == blob.metadata

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.PageBlob
    blob.metadata = None
    blob.snapshot = 'abc'
    ase.populate_from_blob(mock.MagicMock(), blob)
    assert ase.mode == azmodels.StorageModes.Page
    assert ase.snapshot is not None

    blob.snapshot = None
    ase.populate_from_file(mock.MagicMock(), blob, 'path')
    assert ase.mode == azmodels.StorageModes.File
    assert ase.snapshot is None

    blob.metadata = '{}'
    ase.populate_from_file(
        mock.MagicMock(), blob, None, store_raw_metadata=True)
    assert ase.mode == azmodels.StorageModes.File
    assert ase.raw_metadata == blob.metadata
    assert ase.name == blob.name

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path', azmodels.StorageModes.Append, 'cc',
        'ct')
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.Append
    assert ase.cache_control == 'cc'
    assert ase.content_type == 'ct'

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path', azmodels.StorageModes.Block, None,
        None)
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.Block
    assert ase.cache_control is None
    assert ase.content_type == 'application/octet-stream'

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path', azmodels.StorageModes.File, None,
        None)
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.File

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path', azmodels.StorageModes.Page, None,
        None)
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.Page

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path.vhdx', azmodels.StorageModes.Auto,
        None, None)
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.Page

    ase.populate_from_local(
        mock.MagicMock(), 'cont', 'path.bin', azmodels.StorageModes.Auto,
        None, None)
    assert ase.from_local
    assert ase.mode == azmodels.StorageModes.Block

    ase.size = 456
    ase.append_create = False
    ase.encryption_metadata = blobxfer.models.crypto.EncryptionMetadata()
    assert ase.size == 456
    assert not ase.append_create
    assert ase.encryption_metadata is not None

    ase = azmodels.StorageEntity(container=None)
    ase.populate_from_arbitrary_url('https://host/remote/path', 10)
    assert ase.is_arbitrary_url
    assert ase.size == 10
    assert ase.path == 'https://host/remote/path'
