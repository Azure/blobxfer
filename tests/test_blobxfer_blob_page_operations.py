# coding=utf-8
"""Tests for models"""

# stdlib imports
# non-stdlib imports
import azure.storage
import pytest
# local imports
import blobxfer.models as models
# module under test
import blobxfer.blob.page.operations as ops


def test_create_client():
    sa = models.AzureStorageAccount('name', 'key', 'endpoint')
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSharedKeyAuthentication)

    sa = models.AzureStorageAccount('name', '?key&sig=key', 'endpoint')
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.blob.PageBlobService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSASAuthentication)
