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
import azure.common
import azure.storage.blob.models
# local imports
import blobxfer.models

# create logger
logger = logging.getLogger(__name__)


def check_if_single_blob(client, container, prefix, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, str, int) -> bool
    """Check if prefix is a single blob or multiple blobs
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    :param int timeout: timeout
    :rtype: bool
    :return: if prefix in container is a single blob
    """
    try:
        client.get_blob_properties(
            container_name=container, blob_name=prefix, timeout=timeout)
    except azure.common.AzureMissingResourceHttpError:
        return False
    return True


def list_blobs(client, container, prefix, mode, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, str, int,
    #        blobxfer.models.AzureStorageModes) ->
    #        azure.storage.blob.models.Blob
    """List blobs in path conforming to mode
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    :param blobxfer.models.AzureStorageModes mode: storage mode
    :param int timeout: timeout
    :rtype: azure.storage.blob.models.Blob
    :return: generator of blobs
    """
    if mode == blobxfer.models.AzureStorageModes.File:
        raise RuntimeError('cannot list Azure Files from blob client')
    blobs = client.list_blobs(
        container_name=container,
        prefix=prefix,
        include=azure.storage.blob.models.Include.METADATA,
        timeout=timeout,
    )
    for blob in blobs:
        if (mode == blobxfer.models.AzureStorageModes.Append and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.AppendBlob):
            continue
        elif (mode == blobxfer.models.AzureStorageModes.Block and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.BlockBlob):
            continue
        elif (mode == blobxfer.models.AzureStorageModes.Page and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.PageBlob):
            continue
        # auto or match, yield the blob
        yield blob
