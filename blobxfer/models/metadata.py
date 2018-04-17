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
import collections
import json
import logging
# non-stdlib imports
# local imports
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
JSON_KEY_BLOBXFER_METADATA = 'blobxfer_metadata'
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
# named tuples
PosixFileAttr = collections.namedtuple(
    'PosixFileAttr', [
        'gid',
        'mode',
        'uid',
    ]
)
WindowsFileAttr = collections.namedtuple(
    'WindowsFileAttr', [
    ]
)
VectoredStripe = collections.namedtuple(
    'VectoredStripe', [
        'next',
        'offset_start',
        'slice_id',
        'total_size',
        'total_slices',
    ]
)
VectoredNextEntry = collections.namedtuple(
    'VectoredNextEntry', [
        'storage_account_name',
        'endpoint',
        'container',
        'name',
    ]
)
_FILEATTR_WARNED_ON_WINDOWS = False


def get_md5_from_metadata(ase):
    # type: (blobxfer.models.azure.StorageEntity) -> str
    """Get MD5 from properties or metadata
    :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
    :rtype: str or None
    :return: md5
    """
    # if encryption metadata is present, check for pre-encryption
    # md5 in blobxfer extensions
    md5 = None
    if ase.is_encrypted:
        try:
            md5 = ase.encryption_metadata.blobxfer_extensions.\
                pre_encrypted_content_md5
        except AttributeError:
            # this can happen if partial metadata is present
            md5 = None
    if blobxfer.util.is_none_or_empty(md5):
        md5 = ase.md5
    return md5


def generate_fileattr_metadata(local_path, metadata):
    # type: (blobxfer.models.upload.LocalPath, dict) -> dict
    """Generate file attribute metadata dict
    :param blobxfer.models.upload.LocalPath local_path: local path
    :param dict metadata: existing metadata dict
    :rtype: dict
    :return: merged metadata dictionary
    """
    if blobxfer.util.on_windows():
        global _FILEATTR_WARNED_ON_WINDOWS
        if not _FILEATTR_WARNED_ON_WINDOWS:
            _FILEATTR_WARNED_ON_WINDOWS = True
            logger.warning(
                'file attributes store/restore on Windows is not '
                'supported yet')
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


def fileattr_from_metadata(md):
    # type: (dict) -> collections.namedtuple
    """Convert fileattr metadata in json metadata
    :param dict md: metadata dictionary
    :rtype: PosixFileAttr or WindowsFileAttr or None
    :return: fileattr metadata
    """
    try:
        mdattr = json.loads(
            md[JSON_KEY_BLOBXFER_METADATA])[_JSON_KEY_FILE_ATTRIBUTES]
    except (KeyError, TypeError):
        return None
    else:
        if blobxfer.util.on_windows():
            global _FILEATTR_WARNED_ON_WINDOWS
            if not _FILEATTR_WARNED_ON_WINDOWS:
                _FILEATTR_WARNED_ON_WINDOWS = True
                logger.warning(
                    'file attributes store/restore on Windows is not '
                    'supported yet')
            fileattr = None
        else:
            try:
                fileattr = PosixFileAttr(
                    mode=mdattr[_JSON_KEY_FILE_ATTRIBUTES_POSIX][
                        _JSON_KEY_FILE_ATTRIBUTES_MODE],
                    uid=mdattr[_JSON_KEY_FILE_ATTRIBUTES_POSIX][
                        _JSON_KEY_FILE_ATTRIBUTES_UID],
                    gid=mdattr[_JSON_KEY_FILE_ATTRIBUTES_POSIX][
                        _JSON_KEY_FILE_ATTRIBUTES_GID],
                )
            except KeyError:
                fileattr = None
        return fileattr


def create_vectored_io_next_entry(ase):
    # type: (blobxfer.models.azure.StorageEntity) -> str
    """Create Vectored IO next entry id
    :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
    :rtype: str
    :return: vectored io next entry
    """
    return ';'.join(
        (ase.client.primary_endpoint, ase.container, ase.name)
    )


def explode_vectored_io_next_entry(entry):
    # type: (str, int) -> str
    """Explode next vectored io entry
    :param str entry: next entry
    :rtype: VectoredNextEntry
    :return: vectored next entry
    """
    tmp = entry.split(';')
    _sa = tmp[0].split('.')
    return VectoredNextEntry(
        storage_account_name=_sa[0],
        endpoint='.'.join(_sa[2:]),
        container=tmp[1],
        name=tmp[2],
    )


def remove_vectored_io_slice_suffix_from_name(name, slice):
    # type: (str, int) -> str
    """Remove vectored io (stripe) slice suffix from a given name
    :param str name: entity name
    :param int slice: slice num
    :rtype: str
    :return: name without suffix
    """
    suffix = '.bxslice-{}'.format(slice)
    if name.endswith(suffix):
        return name[:-len(suffix)]
    else:
        return name


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


def vectored_io_from_metadata(md):
    # type: (dict) -> collections.namedtuple
    """Convert vectored io metadata in json metadata
    :param dict md: metadata dictionary
    :rtype: VectoredStripe or None
    :return: vectored io metadata
    """
    try:
        mdattr = json.loads(
            md[JSON_KEY_BLOBXFER_METADATA])[_JSON_KEY_VECTORED_IO]
    except (KeyError, TypeError):
        pass
    else:
        if mdattr[_JSON_KEY_VECTORED_IO_MODE] == _JSON_KEY_VECTORED_IO_STRIPE:
            mdstripe = mdattr[_JSON_KEY_VECTORED_IO_STRIPE]
            try:
                nextptr = explode_vectored_io_next_entry(
                    mdstripe[_JSON_KEY_VECTORED_IO_STRIPE_NEXT])
            except (KeyError, AttributeError):
                nextptr = None
            vio = VectoredStripe(
                total_size=mdstripe[_JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SIZE],
                offset_start=mdstripe[
                    _JSON_KEY_VECTORED_IO_STRIPE_OFFSET_START],
                total_slices=mdstripe[
                    _JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SLICES],
                slice_id=mdstripe[_JSON_KEY_VECTORED_IO_STRIPE_SLICE_ID],
                next=nextptr,
            )
            return vio
        else:
            raise RuntimeError('Cannot handle Vectored IO mode: {}'.format(
                mdattr[_JSON_KEY_VECTORED_IO_MODE]))
    return None
