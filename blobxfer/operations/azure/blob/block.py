# Copyright (c) Microsoft Corporation
#
# All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# compat imports
from __future__ import absolute_import, division, print_function
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip
)
# stdlib imports
import logging
# non-stdlib imports
import azure.storage.blob
# local imports
import blobxfer.retry

# create logger
logger = logging.getLogger(__name__)


def create_client(storage_account, timeout, proxy):
    # type: (blobxfer.operations.azure.StorageAccount,
    #        blobxfer.models.options.Timeout,
    #        blobxfer.models.options.HttpProxy) -> BlockBlobService
    """Create block blob client
    :param blobxfer.operations.azure.StorageAccount storage_account:
        storage account
    :param blobxfer.models.options.Timeout timeout: timeout
    :param blobxfer.models.options.HttpProxy proxy: proxy
    :rtype: azure.storage.blob.BlockBlobService
    :return: block blob service client
    """
    if storage_account.is_sas:
        client = azure.storage.blob.BlockBlobService(
            account_name=storage_account.name,
            sas_token=storage_account.key,
            endpoint_suffix=storage_account.endpoint,
            request_session=storage_account.session,
            socket_timeout=timeout.timeout)
    else:
        client = azure.storage.blob.BlockBlobService(
            account_name=storage_account.name,
            account_key=storage_account.key,
            endpoint_suffix=storage_account.endpoint,
            request_session=storage_account.session,
            socket_timeout=timeout.timeout)
    # set proxy
    if proxy is not None:
        client.set_proxy(
            proxy.host, proxy.port, proxy.username, proxy.password)
    # set retry policy
    client.retry = blobxfer.retry.ExponentialRetryWithMaxWait(
        max_retries=timeout.max_retries).retry
    return client


def create_blob(ase, data, md5, metadata, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, bytes, str, dict,
    #        int) -> None
    """Create one shot block blob
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param bytes data: blob data
    :param str md5: md5 as base64
    :param dict metadata: metadata kv pairs
    :param int timeout: timeout
    """
    ase.client._put_blob(
        container_name=ase.container,
        blob_name=ase.name,
        blob=data,
        content_settings=azure.storage.blob.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(ase.name),
            content_md5=md5,
        ),
        metadata=metadata,
        validate_content=False,  # integrity is enforced with HTTPS
        timeout=timeout)  # noqa


def _format_block_id(chunk_num):
    # type: (int) -> str
    """Create a block id given a block (chunk) number
    :param int chunk_num: chunk number
    :rtype: str
    :return: block id
    """
    return '{0:08d}'.format(chunk_num)


def put_block(ase, offsets, data, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity,
    #        blobxfer.models.upload.Offsets, bytes, int) -> None
    """Puts a block into remote blob
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param blobxfer.models.upload.Offsets offsets: upload offsets
    :param bytes data: data
    :param int timeout: timeout
    """
    ase.client.put_block(
        container_name=ase.container,
        blob_name=ase.name,
        block=data,
        block_id=_format_block_id(offsets.chunk_num),
        validate_content=False,  # integrity is enforced with HTTPS
        timeout=timeout)  # noqa


def put_block_list(ase, last_block_num, md5, metadata, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, bytes, str, dict,
    #        int) -> None
    """Create block blob from blocks
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int last_block_num: last block number (chunk_num)
    :param str md5: md5 as base64
    :param dict metadata: metadata kv pairs
    :param int timeout: timeout
    """
    # construct block list
    block_list = [
        azure.storage.blob.BlobBlock(id=_format_block_id(x))
        for x in range(0, last_block_num + 1)
    ]
    ase.client.put_block_list(
        container_name=ase.container,
        blob_name=ase.name,
        block_list=block_list,
        content_settings=azure.storage.blob.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(ase.name),
            content_md5=md5,
        ),
        metadata=metadata,
        validate_content=False,  # integrity is enforced with HTTPS
        timeout=timeout)


def get_committed_block_list(ase, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, int) -> list
    """Get committed block list
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int timeout: timeout
    :rtype: list
    :return: list of committed blocks
    """
    if blobxfer.util.blob_is_snapshot(ase.name):
        blob_name, snapshot = blobxfer.util.parse_blob_snapshot_parameter(
            ase.name)
    else:
        blob_name = ase.name
        snapshot = None
    return ase.client.get_block_list(
        container_name=ase.container,
        blob_name=blob_name,
        snapshot=snapshot,
        block_list_type=azure.storage.blob.BlockListType.Committed,
        timeout=timeout).committed_blocks


def set_blob_access_tier(ase, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, int) -> None
    """Set blob access tier
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int timeout: timeout
    """
    ase.client.set_standard_blob_tier(
        container_name=ase.container,
        blob_name=ase.name,
        standard_blob_tier=ase.access_tier,
        timeout=timeout)  # noqa
