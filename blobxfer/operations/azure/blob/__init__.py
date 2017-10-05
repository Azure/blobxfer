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
import blobxfer.models.azure
import blobxfer.util

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
    if blobxfer.util.blob_is_snapshot(prefix):
        return True
    try:
        client.get_blob_properties(
            container_name=container, blob_name=prefix, timeout=timeout)
    except azure.common.AzureMissingResourceHttpError:
        return False
    return True


def get_blob_properties(client, container, prefix, mode, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, str,
    #        blobxfer.models.azure.StorageModes, int) ->
    #        azure.storage.blob.models.Blob
    """Get blob properties
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    :param blobxfer.models.azure.StorageModes mode: storage mode
    :param int timeout: timeout
    :rtype: azure.storage.blob.models.Blob
    :return: blob
    """
    if mode == blobxfer.models.azure.StorageModes.File:
        raise RuntimeError(
            'cannot list Azure Blobs with incompatible mode: {}'.format(
                mode))
    try:
        blob = client.get_blob_properties(
            container_name=container, blob_name=prefix, timeout=timeout)
    except azure.common.AzureMissingResourceHttpError:
        return None
    if ((mode == blobxfer.models.azure.StorageModes.Append and
         blob.properties.blob_type !=
         azure.storage.blob.models._BlobTypes.AppendBlob) or
            (mode == blobxfer.models.azure.StorageModes.Block and
             blob.properties.blob_type !=
             azure.storage.blob.models._BlobTypes.BlockBlob) or
            (mode == blobxfer.models.azure.StorageModes.Page and
             blob.properties.blob_type !=
             azure.storage.blob.models._BlobTypes.PageBlob)):
        raise RuntimeError(
            'existing blob type {} mismatch with mode {}'.format(
                blob.properties.blob_type, mode))
    return blob


def list_blobs(client, container, prefix, mode, recursive, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, str,
    #        blobxfer.models.azure.StorageModes, bool, int) ->
    #        azure.storage.blob.models.Blob
    """List blobs in path conforming to mode
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str prefix: path prefix
    :param blobxfer.models.azure.StorageModes mode: storage mode
    :param bool recursive: recursive
    :param int timeout: timeout
    :rtype: azure.storage.blob.models.Blob
    :return: generator of blobs
    """
    if mode == blobxfer.models.azure.StorageModes.File:
        raise RuntimeError('cannot list Azure Files from blob client')
    if blobxfer.util.blob_is_snapshot(prefix):
        base_blob, snapshot = blobxfer.util.parse_blob_snapshot_parameter(
            prefix)
        blob = client.get_blob_properties(
            container_name=container, blob_name=base_blob, snapshot=snapshot,
            timeout=timeout)
        yield blob
        return
    blobs = client.list_blobs(
        container_name=container,
        prefix=prefix if blobxfer.util.is_not_empty(prefix) else None,
        include=azure.storage.blob.models.Include.METADATA,
        timeout=timeout,
    )
    for blob in blobs:
        if (mode == blobxfer.models.azure.StorageModes.Append and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.AppendBlob):
            continue
        elif (mode == blobxfer.models.azure.StorageModes.Block and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.BlockBlob):
            continue
        elif (mode == blobxfer.models.azure.StorageModes.Page and
                blob.properties.blob_type !=
                azure.storage.blob.models._BlobTypes.PageBlob):
            continue
        if not recursive and '/' in blob.name:
            continue
        # auto or match, yield the blob
        yield blob


def list_all_blobs(client, container, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, int) ->
    #        azure.storage.blob.models.Blob
    """List all blobs in a container
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param int timeout: timeout
    :rtype: azure.storage.blob.models.Blob
    :return: generator of blobs
    """
    blobs = client.list_blobs(
        container_name=container,
        prefix=None,
        timeout=timeout,
    )
    for blob in blobs:
        yield blob


def delete_blob(client, container, name, timeout=None):
    # type: (azure.storage.blob.BaseBlobService, str, str, int) -> None
    """Delete blob, including all associated snapshots
    :param azure.storage.blob.BaseBlobService client: blob client
    :param str container: container
    :param str name: blob name
    :param int timeout: timeout
    """
    client.delete_blob(
        container_name=container,
        blob_name=name,
        delete_snapshots=azure.storage.blob.models.DeleteSnapshot.Include,
        timeout=timeout,
    )  # noqa


def get_blob_range(ase, offsets, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity,
    #        blobxfer.models.download.Offsets, int) -> bytes
    """Retrieve blob range
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param blobxfer.models.download.Offsets offsets: download offsets
    :param int timeout: timeout
    :rtype: bytes
    :return: content for blob range
    """
    return ase.client._get_blob(
        container_name=ase.container,
        blob_name=ase.name,
        snapshot=ase.snapshot,
        start_range=offsets.range_start,
        end_range=offsets.range_end,
        validate_content=False,  # HTTPS takes care of integrity during xfer
        timeout=timeout,
    ).content


def create_container(ase, containers_created, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, set, int) -> None
    """Create blob container
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param set containers_created: containers already created map
    :param int timeout: timeout
    """
    # check if auth allows create container
    if not ase.create_containers:
        return
    key = ase.client.account_name + ':blob=' + ase.container
    if key in containers_created:
        return
    if ase.client.create_container(
            container_name=ase.container,
            fail_on_exist=False,
            timeout=timeout):
        logger.info(
            'created blob container {} on storage account {}'.format(
                ase.container, ase.client.account_name))
    # always add to set (as it could be pre-existing)
    containers_created.add(key)


def set_blob_md5(ase, md5, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, str, int) -> None
    """Set blob properties MD5
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param str md5: md5 as base64
    :param int timeout: timeout
    """
    ase.client.set_blob_properties(
        container_name=ase.container,
        blob_name=ase.name,
        content_settings=azure.storage.blob.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(ase.name),
            content_md5=md5,
        ),
        timeout=timeout)  # noqa


def set_blob_metadata(ase, metadata, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, dict, int) -> None
    """Set blob metadata
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param dict metadata: metadata kv pairs
    :param int timeout: timeout
    """
    ase.client.set_blob_metadata(
        container_name=ase.container,
        blob_name=ase.name,
        metadata=metadata,
        timeout=timeout)  # noqa
