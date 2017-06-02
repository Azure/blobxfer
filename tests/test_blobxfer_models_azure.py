# coding=utf-8
"""Tests for models azure"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage
import azure.storage.blob
import azure.storage.file
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
    ase.populate_from_blob(mock.MagicMock(), blob)

    assert ase.client is not None
    assert ase.name == 'name'
    assert ase.lmt == 'lmt'
    assert ase.size == 123
    assert ase.md5 == 'abc'
    assert ase.snapshot is None
    assert ase.mode == azmodels.StorageModes.Block

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.AppendBlob
    ase.populate_from_blob(mock.MagicMock(), blob)
    assert ase.mode == azmodels.StorageModes.Append

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.PageBlob
    blob.snapshot = 'abc'
    ase.populate_from_blob(mock.MagicMock(), blob)
    assert ase.mode == azmodels.StorageModes.Page
    assert ase.snapshot is not None

    blob.snapshot = None
    ase.populate_from_file(mock.MagicMock(), blob, 'path')
    assert ase.mode == azmodels.StorageModes.File
    assert ase.snapshot is None
