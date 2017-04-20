# coding=utf-8
"""Tests for operations: block blob"""

# stdlib imports
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