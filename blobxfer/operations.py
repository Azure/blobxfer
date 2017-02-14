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
# local imports
from .models import (  # noqa
    AzureStorageCredentials,
    AzureStorageModes,
    DownloadSpecification,
    FileDescriptor,
)
from .blob.operations import check_if_single_blob
from .file.operations import check_if_single_file
from .util import explode_azure_path


def ensure_local_destination(creds, spec):
    """Ensure a local destination path given a download spec
    :param AzureStorageCredentials creds: creds
    :param DownloadSpecification spec: download spec
    """
    # ensure destination path is writable given the source
    if len(spec.sources) < 1:
        raise RuntimeError('no sources to download from specified')
    # set is_dir for destination
    spec.destination.is_dir = True
    if len(spec.sources) == 1:
        # we need to query the source to see if this is a directory
        rpath = str(spec.sources[0].paths[0])
        sa = creds.get_storage_account(
            spec.sources[0].lookup_storage_account(rpath))
        cont, dir = explode_azure_path(rpath)
        if spec.options.mode == AzureStorageModes.File:
            if check_if_single_file(sa.file_client, cont, dir):
                spec.destination.is_dir = False
        else:
            if check_if_single_blob(sa.block_blob_client, cont, dir):
                spec.destination.is_dir = False
    logging.debug('dest is_dir={} for {} specs'.format(
        spec.destination.is_dir, len(spec.sources)))
    # ensure destination path
    spec.destination.ensure_path_exists()


def file_chunks(fd, chunk_size):
    # type: (FileDescriptor, int) -> bytes
    """Generator for getting file chunks of a file
    :param FileDescriptor fd: file descriptor
    :param int chunk_size: the amount of data to read
    :rtype: bytes
    :return: file data
    """
    with fd.path.open('rb') as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            yield data


def read_file_chunk(fd, chunk_num, chunk_size):
    # type: (FileDescriptor, int, int) -> bytes
    """Read file chunk
    :param FileDescriptor fd: file descriptor
    :param int chunk_num: chunk number
    :param int chunk_size: the amount of data to read
    :rtype: bytes
    :return: file data
    """
    offset = chunk_num * chunk_size
    with fd.path.open('rb') as f:
        f.seek(offset, 0)
        return f.read(chunk_size)


def write_file_chunk(fd, chunk_num, chunk_size, data):
    # type: (FileDescriptor, int, int, bytes) -> None
    """Write file chunk
    :param FileDescriptor fd: file descriptor
    :param int chunk_num: chunk number
    :param int chunk_size: the amount of data to read
    :rtype: bytes
    :return: file data
    """
    offset = chunk_num * chunk_size
    with fd.path.open('wb') as f:
        f.seek(offset, 0)
        f.write(data)
