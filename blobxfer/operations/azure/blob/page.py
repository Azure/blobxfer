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
    #        blobxfer.models.options.HttpProxy) -> PageBlobService
    """Create block blob client
    :param blobxfer.operations.azure.StorageAccount storage_account:
        storage account
    :param blobxfer.models.options.Timeout timeout: timeout
    :param blobxfer.models.options.HttpProxy proxy: proxy
    :rtype: PageBlobService
    :return: block blob service client
    """
    if storage_account.is_sas:
        client = azure.storage.blob.PageBlobService(
            account_name=storage_account.name,
            sas_token=storage_account.key,
            endpoint_suffix=storage_account.endpoint,
            request_session=storage_account.session,
            socket_timeout=timeout.timeout)
    else:
        client = azure.storage.blob.PageBlobService(
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


def create_blob(ase, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, int) -> None
    """Create page blob
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int timeout: timeout
    """
    ase.client.create_blob(
        container_name=ase.container,
        blob_name=ase.name,
        content_length=blobxfer.util.page_align_content_length(ase.size),
        content_settings=azure.storage.blob.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(ase.name)
        ),
        timeout=timeout)  # noqa


def put_page(ase, page_start, page_end, data, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity,
    #        int, int, bytes, int) -> None
    """Puts a page into remote blob
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int page_start: page range start
    :param int page_end: page range end
    :param bytes data: data
    :param int timeout: timeout
    """
    ase.client.update_page(
        container_name=ase.container,
        blob_name=ase.name,
        page=data,
        start_range=page_start,
        end_range=page_end,
        validate_content=False,  # integrity is enforced with HTTPS
        timeout=timeout)  # noqa


def resize_blob(ase, size, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, int, int) -> None
    """Resizes a page blob
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int size: content length
    :param int timeout: timeout
    """
    ase.client.resize_blob(
        container_name=ase.container,
        blob_name=ase.name,
        content_length=blobxfer.util.page_align_content_length(size),
        timeout=timeout)  # noqa
