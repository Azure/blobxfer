# coding=utf-8
"""Tests for models"""

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
import blobxfer.operations.azure.blob.page as ops


def test_create_client():
    to = mock.MagicMock()
    to.max_retries = None

    sa = azops.StorageAccount(
        'name', 'key', 'core.windows.net', 10, to, mock.MagicMock())
    client = ops.create_client(sa, to, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSharedKeyAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
    assert client._httpclient.proxies is not None

    sa = azops.StorageAccount(
        'name', '?key&sig=key', 'core.windows.net', 10, to, None)
    client = ops.create_client(sa, to, None)
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSASAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
    assert client._httpclient.proxies is None
