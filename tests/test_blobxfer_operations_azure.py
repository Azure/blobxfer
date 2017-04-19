# coding=utf-8
"""Tests for operations azure"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage
import azure.storage.blob
import azure.storage.file
import pytest
# module under test
import blobxfer.models.azure as azmodels
import blobxfer.operations.azure as azops


def test_storage_credentials():
    creds = azops.StorageCredentials(mock.MagicMock())
    creds.add_storage_account('sa1', 'somekey1', 'endpoint')

    a = creds.get_storage_account('sa1')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'endpoint'
    assert isinstance(
        a.append_blob_client, azure.storage.blob.AppendBlobService)
    assert isinstance(
        a.block_blob_client, azure.storage.blob.BlockBlobService)
    assert isinstance(
        a.file_client, azure.storage.file.FileService)
    assert isinstance(
        a.page_blob_client, azure.storage.blob.PageBlobService)

    with pytest.raises(KeyError):
        a = creds.get_storage_account('sa2')

    with pytest.raises(ValueError):
        creds.add_storage_account('sa1', 'somekeyxx', 'endpoint')

    creds.add_storage_account('sa2', 'somekey2', 'endpoint2')
    a = creds.get_storage_account('sa1')
    b = creds.get_storage_account('sa2')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'endpoint'
    assert b.name == 'sa2'
    assert b.key == 'somekey2'
    assert b.endpoint == 'endpoint2'


def test_key_is_sas():
    a = azops.StorageAccount('name', 'abcdef', 'endpoint', 10)
    assert not a.is_sas

    a = azops.StorageAccount('name', 'abcdef&blah', 'endpoint', 10)
    assert not a.is_sas

    a = azops.StorageAccount('name', '?abcdef', 'endpoint', 10)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'endpoint', 10)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sv=0&sr=1&sig=2', 'endpoint', 10)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sig=0&sv=0&sr=1&se=2', 'endpoint', 10)
    assert a.is_sas


def test_azuresourcepath():
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    with pytest.raises(RuntimeError):
        asp.add_path_with_storage_account('x', 'x')

    assert 'sa' == asp.lookup_storage_account(p)


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.file.list_files')
def test_azuresourcepath_files(patched_lf, patched_em):
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.File
    creds = mock.MagicMock()
    creds.get_storage_account = mock.MagicMock()
    sa = mock.MagicMock()
    sa.file_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    f = azure.storage.file.models.File(name='name')
    patched_lf.side_effect = [[f]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    fe = azure.storage.file.models.File(name='name')
    fe.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lf.side_effect = [[fe]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.blob.list_blobs')
def test_azuresourcepath_blobs(patched_lb, patched_em):
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.Auto
    creds = mock.MagicMock()
    creds.get_storage_account = mock.MagicMock()
    sa = mock.MagicMock()
    sa.block_blob_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    b = azure.storage.blob.models.Blob(name='name')
    patched_lb.side_effect = [[b]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    be = azure.storage.blob.models.Blob(name='name')
    be.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lb.side_effect = [[be]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1
