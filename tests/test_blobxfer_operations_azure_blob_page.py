# coding=utf-8
"""Tests for models"""

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
import blobxfer.operations.azure.blob.page as ops


def test_create_client():
    sa = azops.StorageAccount('name', 'key', 'endpoint', 10, mock.MagicMock())
    client = ops.create_client(sa, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSharedKeyAuthentication)

    sa = azops.StorageAccount(
        'name', '?key&sig=key', 'endpoint', 10, mock.MagicMock())
    client = ops.create_client(sa, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSASAuthentication)
