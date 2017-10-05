# coding=utf-8
"""Tests for operations: blob append"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage.common
# local imports
import blobxfer.version
# module under test
import blobxfer.operations.azure as azops
import blobxfer.operations.azure.blob.append as ops


def test_create_client():
    sa = azops.StorageAccount('name', 'key', 'endpoint', 10, mock.MagicMock())
    client = ops.create_client(sa, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.AppendBlobService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSharedKeyAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))

    sa = azops.StorageAccount(
        'name', '?key&sig=key', 'endpoint', 10, mock.MagicMock())
    client = ops.create_client(sa, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.AppendBlobService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSASAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
