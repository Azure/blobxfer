# coding=utf-8
"""Tests for general blob operations"""

# stdlib imports
import mock
# non-stdlib imports
import azure.common
import azure.storage.blob
import pytest
# local imports
import blobxfer.models as models
# module under test
import blobxfer.blob.operations as ops


def test_check_if_single_blob():
    client = mock.MagicMock()
    client.get_blob_properties.return_value = True

    result = ops.check_if_single_blob(client, 'a', 'b/c')
    assert result

    result = ops.check_if_single_blob(
        client, 'a', 'a?snapshot=2017-02-23T22:21:14.8121864Z')
    assert result

    client = mock.MagicMock()
    client.get_blob_properties = mock.MagicMock()
    client.get_blob_properties.side_effect = \
        azure.common.AzureMissingResourceHttpError('msg', 404)

    result = ops.check_if_single_blob(client, 'a', 'b/c')
    assert not result


def test_list_blobs():
    with pytest.raises(RuntimeError):
        for blob in ops.list_blobs(
                None, 'cont', 'prefix', models.AzureStorageModes.File):
            pass

    _blob = azure.storage.blob.models.Blob(name='name')
    _blob.properties = azure.storage.blob.models.BlobProperties()
    client = mock.MagicMock()
    client.list_blobs.return_value = [_blob]

    i = 0
    for blob in ops.list_blobs(
            client, 'cont', 'prefix', models.AzureStorageModes.Auto):
        i += 1
        assert blob.name == 'name'
    assert i == 1

    _blob.properties.blob_type = \
        azure.storage.blob.models._BlobTypes.AppendBlob
    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', models.AzureStorageModes.Block):
        i += 1
        assert blob.name == 'name'
    assert i == 0

    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', models.AzureStorageModes.Page):
        i += 1
        assert blob.name == 'name'
    assert i == 0

    _blob.properties.blob_type = \
        azure.storage.blob.models._BlobTypes.BlockBlob
    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', models.AzureStorageModes.Append):
        i += 1
        assert blob.name == 'name'
    assert i == 0

    _blob.snapshot = '2017-02-23T22:21:14.8121864Z'
    client.get_blob_properties.return_value = _blob
    i = 0
    for blob in ops.list_blobs(
            client, 'cont',
            'a?snapshot=2017-02-23T22:21:14.8121864Z',
            models.AzureStorageModes.Auto):
        i += 1
        assert blob.name == 'name'
        assert blob.snapshot == _blob.snapshot
    assert i == 1


def test_get_blob_range():
    ase = mock.MagicMock()
    ret = mock.MagicMock()
    ret.content = b'\0'
    ase.client._get_blob.return_value = ret
    ase.container = 'cont'
    ase.name = 'name'
    ase.snapshot = None
    offsets = mock.MagicMock()
    offsets.start_range = 0
    offsets.end_range = 1

    assert ops.get_blob_range(ase, offsets) == ret.content
