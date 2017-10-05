# coding=utf-8
"""Tests for general blob operations"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.common
import azure.storage.blob
import pytest
# local imports
import blobxfer.models.azure as azmodels
# module under test
import blobxfer.operations.azure.blob as ops


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


def test_get_blob_properties():
    with pytest.raises(RuntimeError):
        ops.get_blob_properties(
            None, 'cont', None, azmodels.StorageModes.File)

    client = mock.MagicMock()
    blob = mock.MagicMock()
    client.get_blob_properties.side_effect = \
        azure.common.AzureMissingResourceHttpError('msg', 'code')

    ret = ops.get_blob_properties(
        client, 'cont', None, azmodels.StorageModes.Append)
    assert ret is None

    blob = mock.MagicMock()
    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.PageBlob
    client = mock.MagicMock()
    client.get_blob_properties.return_value = blob

    with pytest.raises(RuntimeError):
        ops.get_blob_properties(
            client, 'cont', None, azmodels.StorageModes.Append)

    with pytest.raises(RuntimeError):
        ops.get_blob_properties(
            client, 'cont', None, azmodels.StorageModes.Block)

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.BlockBlob
    with pytest.raises(RuntimeError):
        ops.get_blob_properties(
            client, 'cont', None, azmodels.StorageModes.Page)

    ret = ops.get_blob_properties(
        client, 'cont', None, azmodels.StorageModes.Block)
    assert ret == blob


def test_list_blobs():
    with pytest.raises(RuntimeError):
        for blob in ops.list_blobs(
                None, 'cont', 'prefix', azmodels.StorageModes.File, True):
            pass

    _blob = azure.storage.blob.models.Blob(name='dir/name')
    _blob.properties = azure.storage.blob.models.BlobProperties()
    client = mock.MagicMock()
    client.list_blobs.return_value = [_blob]

    i = 0
    for blob in ops.list_blobs(
            client, 'cont', 'prefix', azmodels.StorageModes.Auto, False):
        i += 1
        assert blob.name == _blob.name
    assert i == 0

    i = 0
    for blob in ops.list_blobs(
            client, 'cont', 'prefix', azmodels.StorageModes.Auto, True):
        i += 1
        assert blob.name == _blob.name
    assert i == 1

    _blob.properties.blob_type = \
        azure.storage.blob.models._BlobTypes.AppendBlob
    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', azmodels.StorageModes.Block, True):
        i += 1
        assert blob.name == _blob.name
    assert i == 0

    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', azmodels.StorageModes.Page, True):
        i += 1
        assert blob.name == _blob.name
    assert i == 0

    _blob.properties.blob_type = \
        azure.storage.blob.models._BlobTypes.BlockBlob
    i = 0
    for blob in ops.list_blobs(
            client, 'dir', 'prefix', azmodels.StorageModes.Append, True):
        i += 1
        assert blob.name == _blob.name
    assert i == 0

    _blob.snapshot = '2017-02-23T22:21:14.8121864Z'
    client.get_blob_properties.return_value = _blob
    i = 0
    for blob in ops.list_blobs(
            client, 'cont',
            'a?snapshot=2017-02-23T22:21:14.8121864Z',
            azmodels.StorageModes.Auto,
            True):
        i += 1
        assert blob.name == _blob.name
        assert blob.snapshot == _blob.snapshot
    assert i == 1


def test_list_all_blobs():
    client = mock.MagicMock()
    blob = mock.MagicMock()
    client.list_blobs.return_value = [blob, blob]

    assert len(list(ops.list_all_blobs(client, 'cont'))) == 2


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


def test_create_container():
    ase = mock.MagicMock()
    ase.create_containers = False

    ops.create_container(ase, None)
    assert ase.client.create_container.call_count == 0

    ase.create_containers = True
    ase.client.account_name = 'sa'
    ase.container = 'cont'

    cc = set()
    ase.client.create_container.return_value = True
    ops.create_container(ase, cc)
    assert len(cc) == 1

    ase.client.create_container.return_value = False
    ops.create_container(ase, cc)
    assert len(cc) == 1

    ase.container = 'cont2'
    ops.create_container(ase, cc)
    assert len(cc) == 2

    ops.create_container(ase, cc)
    assert len(cc) == 2
