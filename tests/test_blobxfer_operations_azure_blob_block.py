# coding=utf-8
"""Tests for operations: block blob"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage.common
# local imports
import blobxfer.version
import blobxfer.models.azure
# module under test
import blobxfer.operations.azure as azops
import blobxfer.operations.azure.blob.block as ops


def test_create_client():
    to = mock.MagicMock()
    to.max_retries = None

    sa = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, mock.MagicMock())
    client = ops.create_client(sa, to, mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.blob.BlockBlobService)
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
    assert isinstance(client, azure.storage.blob.BlockBlobService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSASAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
    assert client._httpclient.proxies is None


def test_format_block_id():
    assert '00000001' == ops._format_block_id(1)


def test_put_block_from_url():
    dst_ase = mock.MagicMock()
    dst_ase.client.put_block_from_url = mock.MagicMock()

    src_ase = mock.MagicMock()
    src_ase.path = 'https://host/remote/path'
    src_ase.is_arbitrary_url = True

    offsets = mock.MagicMock()
    offsets.chunk_num = 0

    ops.put_block_from_url(src_ase, dst_ase, offsets)
    assert dst_ase.client.put_block_from_url.call_count == 1

    src_ase.is_arbitrary_url = False

    src_ase.client.account_key = 'key'
    src_ase.client.generate_blob_shared_access_signature.return_value = 'sas'

    ops.put_block_from_url(src_ase, dst_ase, offsets)
    assert dst_ase.client.put_block_from_url.call_count == 2

    src_ase.client.account_key = None
    src_ase.client.sas_token = 'sastoken'

    ops.put_block_from_url(src_ase, dst_ase, offsets)
    assert dst_ase.client.put_block_from_url.call_count == 3

    src_ase.client.account_key = 'key'
    src_ase.client.sas_token = None
    src_ase.mode = blobxfer.models.azure.StorageModes.File
    src_ase.client.generate_file_shared_access_signature.return_value = 'sas'

    ops.put_block_from_url(src_ase, dst_ase, offsets)
    assert dst_ase.client.put_block_from_url.call_count == 4


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
