# coding=utf-8
"""Tests for operations: block blob"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage
# local imports
# module under test
import blobxfer.operations.azure as azops
import blobxfer.operations.azure.blob.block as ops


def test_create_client():
    sa = azops.StorageAccount('name', 'key', 'endpoint', 10)
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.blob.BlockBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSharedKeyAuthentication)

    sa = azops.StorageAccount('name', '?key&sig=key', 'endpoint', 10)
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.blob.BlockBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSASAuthentication)


def test_format_block_id():
    assert '00000001' == ops._format_block_id(1)


def test_put_block_list():
    ase = mock.MagicMock()
    ase.name = 'abc'
    ops.put_block_list(ase, 1, None, None)
    assert ase.client.put_block_list.call_count == 1


def test_get_committed_block_list():
    ase = mock.MagicMock()
    ase.name = 'abc'
    gbl = mock.MagicMock()
    gbl.committed_blocks = 1
    ase.client.get_block_list.return_value = gbl
    assert ops.get_committed_block_list(ase) == 1

    ase.name = 'abc?snapshot=123'
    gbl.committed_blocks = 2
    assert ops.get_committed_block_list(ase) == 2
