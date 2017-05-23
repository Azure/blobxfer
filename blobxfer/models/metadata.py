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
from __future__ import (
    absolute_import, division, print_function, unicode_literals
)
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip)
# stdlib imports
import logging
# non-stdlib imports
# local imports
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
JSON_KEY_BLOBXFER_METADATA = 'BlobxferMetadata'
# file attributes
_JSON_KEY_FILE_ATTRIBUTES = 'FileAttributes'
_JSON_KEY_FILE_ATTRIBUTES_POSIX = 'POSIX'
_JSON_KEY_FILE_ATTRIBUTES_WINDOWS = 'Windows'
_JSON_KEY_FILE_ATTRIBUTES_MODE = 'mode'
_JSON_KEY_FILE_ATTRIBUTES_UID = 'uid'
_JSON_KEY_FILE_ATTRIBUTES_GID = 'gid'
# vectored io
_JSON_KEY_VECTORED_IO = 'VectoredIO'
_JSON_KEY_VECTORED_IO_MODE = 'Mode'
_JSON_KEY_VECTORED_IO_STRIPE = 'Stripe'
_JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SIZE = 'TotalSize'
_JSON_KEY_VECTORED_IO_STRIPE_OFFSET_START = 'OffsetStart'
_JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SLICES = 'TotalSlices'
_JSON_KEY_VECTORED_IO_STRIPE_SLICE_ID = 'SliceId'
_JSON_KEY_VECTORED_IO_STRIPE_NEXT = 'Next'


def generate_fileattr_metadata(local_path, metadata):
    # type: (blobxfer.models.upload.LocalPath, dict) -> dict
    """Generate file attribute metadata dict
    :param blobxfer.models.upload.LocalPath local_path: local path
    :param dict metadata: existing metadata dict
    :rtype: dict
    :return: merged metadata dictionary
    """
    if blobxfer.util.on_windows():
        logger.warning(
            'file attributes store/restore on Windows is not supported yet')
        return None
    else:
        md = {
            _JSON_KEY_FILE_ATTRIBUTES: {
                _JSON_KEY_FILE_ATTRIBUTES_POSIX: {
                    _JSON_KEY_FILE_ATTRIBUTES_MODE: local_path.mode,
                    _JSON_KEY_FILE_ATTRIBUTES_UID: local_path.uid,
                    _JSON_KEY_FILE_ATTRIBUTES_GID: local_path.gid,
                }
            }
        }
        return blobxfer.util.merge_dict(metadata, md)


def restore_fileattr(path, metadata):
    # type: (pathlib.Path, dict) -> None
    """Restore file attributes from metadata
    :param pathlib.Path path: path to modify
    :param dict metadata: existing metadata dict
    """
    if blobxfer.util.on_windows():
        logger.warning(
            'file attributes store/restore on Windows is not supported yet')
    raise NotImplementedError()


def create_vectored_io_next_entry(ase):
    # type: (blobxfer.models.upload.LocalPath) -> str
    """Create Vectored IO next entry id
    :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
    :rtype: str
    :return: vectored io next entry
    """
    return ';'.join(
        (ase.client.primary_endpoint, ase.container, ase.name)
    )


def generate_vectored_io_stripe_metadata(local_path, metadata):
    # type: (blobxfer.models.upload.LocalPath, dict) -> dict
    """Generate vectored io stripe metadata dict
    :param blobxfer.models.upload.LocalPath local_path: local path
    :param dict metadata: existing metadata dict
    :rtype: dict
    :return: merged metadata dictionary
    """
    md = {
        _JSON_KEY_VECTORED_IO: {
            _JSON_KEY_VECTORED_IO_MODE: _JSON_KEY_VECTORED_IO_STRIPE,
            _JSON_KEY_VECTORED_IO_STRIPE: {
                _JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SIZE: local_path.total_size,
                _JSON_KEY_VECTORED_IO_STRIPE_OFFSET_START:
                local_path.view.fd_start,
                _JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SLICES:
                local_path.view.total_slices,
                _JSON_KEY_VECTORED_IO_STRIPE_SLICE_ID:
                local_path.view.slice_num,
                _JSON_KEY_VECTORED_IO_STRIPE_NEXT: local_path.view.next,
            }
        }
    }
    return blobxfer.util.merge_dict(metadata, md)
