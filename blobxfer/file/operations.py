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
from azure.storage.file import FileService
# local imports
from ..util import is_none_or_empty

# create logger
logger = logging.getLogger(__name__)


def create_client(storage_account):
    # type: (blobxfer.models.AzureStorageAccount) -> FileService
    """Create file client
    :param blobxfer.models.AzureStorageAccount storage_account: storage account
    :rtype: FileService
    :return: file service client
    """
    if storage_account.is_sas:
        client = FileService(
            account_name=storage_account.name,
            sas_token=storage_account.key,
            endpoint_suffix=storage_account.endpoint)
    else:
        client = FileService(
            account_name=storage_account.name,
            account_key=storage_account.key,
            endpoint_suffix=storage_account.endpoint)
    return client


def check_if_single_file(client, container, prefix):
    # type: (azure.storage.blob.BaseBlobService, str, str) -> bool
    """List append blobs in path
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    :rtype: bool
    :return: if prefix in container is a single blob
    """
    blobs = client.list_blobs(
        container_name=container, prefix=prefix, num_results=1)
    return is_none_or_empty(blobs.next_marker)


def list_blobs(client, container, prefix, mode):
    # type: (azure.storage.blob.BaseBlobService, str, str,
    #        blobxfer.models.AzureStorageModes) -> list
    """List blobs in path conforming to mode
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    """

    pass
