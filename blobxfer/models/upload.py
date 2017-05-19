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
import enum
import logging
import math
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
import threading
# non-stdlib imports
# local imports
import blobxfer.models
import blobxfer.models.crypto
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_MAX_BLOCK_BLOB_ONESHOT_BYTES = 268435456
_MAX_BLOCK_BLOB_CHUNKSIZE_BYTES = 268435456
_MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES = 4194304


# named tuples
Offsets = collections.namedtuple(
    'Offsets', [
        'chunk_num',
        'block_id',
        'fd_start',
        'num_bytes',
        'range_end',
        'range_start',
        'pad',
    ]
)
LocalPathView = collections.namedtuple(
    'LocalPathView', [
        'fd_end',
        'fd_start',
        'slice_num',
    ]
)


class VectoredIoDistributionMode(enum.Enum):
    Disabled = 'disabled'
    Stripe = 'stripe'
    Replica = 'replica'

    def __str__(self):
        return self.value


class LocalPath(object):
    def __init__(self, parent_path, relative_path, view=None):
        self.parent_path = parent_path
        self.relative_path = relative_path
        # populate properties
        self._stat = self.absolute_path.stat()
        if view is None:
            self.view = LocalPathView(
                fd_start=0,
                fd_end=self.size,
                slice_num=0,
            )
        else:
            self.view = view

    @property
    def absolute_path(self):
        return self.parent_path / self.relative_path

    @property
    def size(self):
        return self._stat.st_size

    @property
    def lmt(self):
        return self._stat.st_mtime

    @property
    def mode(self):
        return str(oct(self._stat.st_mode))

    @property
    def uid(self):
        return self._stat.st_uid

    @property
    def gid(self):
        return self._stat.st_gid


class LocalSourcePath(blobxfer.models._BaseSourcePaths):
    """Local Source Path"""

    def can_rename(self):
        return len(self._paths) == 1 and self._paths[0].is_file()

    def files(self):
        # type: (LocalSourcePaths) -> LocalPath
        """Generator for files in paths
        :param LocalSourcePath self: this
        :rtype: LocalPath
        :return: LocalPath
        """
        for _path in self._paths:
            _ppath = os.path.expandvars(os.path.expanduser(str(_path)))
            _expath = pathlib.Path(_ppath).resolve()
            # check if path is a single file
            tmp = pathlib.Path(_ppath)
            if tmp.is_file():
                if self._inclusion_check(tmp.name):
                    yield LocalPath(
                        parent_path=tmp.parent,
                        relative_path=pathlib.Path(tmp.name)
                    )
                continue
            del tmp
            for entry in blobxfer.util.scantree(_ppath):
                _rpath = pathlib.Path(entry.path).relative_to(_ppath)
                if not self._inclusion_check(_rpath):
                    continue
                yield LocalPath(parent_path=_expath, relative_path=_rpath)


class Specification(object):
    """Upload Specification"""
    def __init__(
            self, upload_options, skip_on_options, local_source_path):
        # type: (Specification, blobxfer.models.options.Upload,
        #        blobxfer.models.options.SkipOn, LocalSourcePath) -> None
        """Ctor for Specification
        :param UploadSpecification self: this
        :param blobxfer.models.options.Upload upload_options: upload options
        :param blobxfer.models.options.SkipOn skip_on_options: skip on options
        :param LocalSourcePath local_source_path: local source path
        """
        self.options = upload_options
        self.skip_on = skip_on_options
        self.destinations = []
        self.sources = local_source_path
        # validate options
        if self.options.rename:
            # ensure only one internal path is present
            if len(self.sources.paths) > 1:
                raise ValueError(
                    'cannot add more than one internal source path if rename '
                    'is specified')
            # check if internal source path is directory and rename is enabled
            if self.sources.paths[0].is_dir():
                raise ValueError(
                    'cannot rename a directory of files to upload')
        if self.options.chunk_size_bytes <= 0:
            raise ValueError('chunk size must be positive')
        if self.options.chunk_size_bytes > _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
            raise ValueError(
                ('chunk size value of {} exceeds maximum allowable '
                 'of {}').format(
                     self.options.chunk_size_bytes,
                     _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES))
        if self.options.one_shot_bytes < 0:
            raise ValueError('one shot bytes value must be at least 0')
        if self.options.one_shot_bytes > _MAX_BLOCK_BLOB_ONESHOT_BYTES:
            raise ValueError(
                ('one shot bytes value of {} exceeds maximum allowable '
                 'of {}').format(
                     self.options.chunk_size_bytes,
                     _MAX_BLOCK_BLOB_ONESHOT_BYTES))

    def add_azure_destination_path(self, dest):
        # type: (Specification,
        #        blobxfer.operations.azure.DestinationPath) -> None
        """Add a remote Azure Destination path
        :param UploadSpecification self: this
        :param blobxfer.operations.azure.DestinationPath dest:
            Remote destination path
        """
        self.destinations.append(dest)


class Descriptor(object):
    """Upload Descriptor"""

    _AES_BLOCKSIZE = blobxfer.models.crypto.AES256_BLOCKSIZE_BYTES

    def __init__(self, lpath, ase, uid, options, resume_mgr):
        # type: (Descriptior, LocalPath,
        #        blobxfer.models.azure.StorageEntity, str,
        #        blobxfer.models.options.Upload,
        #        blobxfer.operations.resume.UploadResumeManager) -> None
        """Ctor for Descriptor
        :param Descriptor self: this
        :param LocalPath lpath: local path
        :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
        :param str uid: unique id
        :param blobxfer.models.options.Upload options: download options
        :param blobxfer.operations.resume.UploadResumeManager resume_mgr:
            upload resume manager
        """
        self.local_path = lpath
        self.unique_id = uid
        self._offset = 0
        self._chunk_num = 0
        self._next_integrity_chunk = 0
        self._finalized = False
        self._meta_lock = threading.Lock()
        self._hasher_lock = threading.Lock()
        self._resume_mgr = resume_mgr
        self._ase = ase
        self.current_iv = None
        self._initialize_encryption(options)
        # calculate the total number of ops required for transfer
        self._compute_remote_size()
        self._adjust_chunk_size(options)
        self._total_chunks = self._compute_total_chunks(self._chunk_size)
        self._outstanding_ops = self._total_chunks
        # initialize integrity checkers
        self.hmac = None
        self.md5 = None
        self._initialize_integrity_checkers(options)

    @property
    def entity(self):
        # type: (Descriptor) -> blobxfer.models.azure.StorageEntity
        """Get linked blobxfer.models.azure.StorageEntity
        :param Descriptor self: this
        :rtype: blobxfer.models.azure.StorageEntity
        :return: blobxfer.models.azure.StorageEntity
        """
        return self._ase

    @property
    def must_compute_md5(self):
        # type: (Descriptor) -> bool
        """Check if MD5 must be computed
        :param Descriptor self: this
        :rtype: bool
        :return: if MD5 must be computed
        """
        return self.md5 is not None

    @property
    def all_operations_completed(self):
        # type: (Descriptor) -> bool
        """All operations are completed
        :param Descriptor self: this
        :rtype: bool
        :return: if all operations completed
        """
        with self._meta_lock:
            return (self._outstanding_ops == 0 and
                    len(self._unchecked_chunks) == 0)

    @property
    def is_resumable(self):
        # type: (Descriptor) -> bool
        """Upload is resume capable
        :param Descriptor self: this
        :rtype: bool
        :return: if resumable
        """
        return self._resume_mgr is not None and self.hmac is None

    @property
    def one_shot(self):
        # type: (Descriptor) -> bool
        """Upload is a one-shot block upload
        :param Descriptor self: this
        :rtype: bool
        :return: is one-shot capable
        """
        return (self._ase.mode == blobxfer.models.azure.StorageModes.Block and
                self._total_chunks == 1)

    def hmac_iv(self, iv):
        # type: (Descriptor, bytes) -> None
        """Send IV through hasher
        :param Descriptor self: this
        :param bytes iv: iv
        """
        with self._hasher_lock:
            self.hmac.update(iv)

    def _initialize_encryption(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Download is resume capable
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        """
        if options.rsa_public_key is not None:
            em = blobxfer.models.crypto.EncryptionMetadata()
            em.create_new_metadata(options.rsa_public_key)
            self.current_iv = em.content_encryption_iv
            self._ase.encryption_metadata = em

    def _compute_remote_size(self):
        # type: (Descriptor, int) -> None
        """Compute total remote file size
        :param Descriptor self: this
        :rtype: int
        :return: remote file size
        """
        size = self.local_path.size
        if size > 0:
            if self._ase.is_encrypted:
                # cipher_len_without_iv = (clear_len / aes_bs + 1) * aes_bs
                allocatesize = (size // self._AES_BLOCKSIZE - 1) * \
                    self._AES_BLOCKSIZE
            else:
                allocatesize = size
            if allocatesize < 0:
                allocatesize = 0
        else:
            allocatesize = 0
        self._ase.size = allocatesize
        logger.debug('remote size for {} is {} bytes'.format(
            self._ase.path, self._ase.size))

    def _adjust_chunk_size(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Adjust chunk size for entity mode
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        """
        self._chunk_size = min((options.chunk_size_bytes, self._ase.size))
        # ensure chunk sizes are compatible with mode
        if self._ase.mode == blobxfer.models.azure.StorageModes.Append:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    'adjusting chunk size to {} for append blobs'.format(
                        self._chunk_size))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Block:
            if self._ase.size <= options.one_shot_bytes:
                self._chunk_size = options.one_shot_bytes
            else:
                if self._chunk_size > _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
                    self._chunk_size = _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
                    logger.debug(
                        'adjusting chunk size to {} for block blobs'.format(
                            self._chunk_size))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.File:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    'adjusting chunk size to {} for files'.format(
                        self._chunk_size))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Page:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    'adjusting chunk size to {} for page blobs'.format(
                        self._chunk_size))

    def _compute_total_chunks(self, chunk_size):
        # type: (Descriptor, int) -> int
        """Compute total number of chunks for entity
        :param Descriptor self: this
        :param int chunk_size: chunk size
        :rtype: int
        :return: num chunks
        """
        try:
            return int(math.ceil(self._ase.size / chunk_size))
        except ZeroDivisionError:
            return 0

    def _initialize_integrity_checkers(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Initialize file integrity checkers
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        """
        if self._ase.is_encrypted:
            # ensure symmetric key exists
            if blobxfer.util.is_none_or_empty(
                    self._ase.encryption_metadata.symmetric_key):
                raise RuntimeError(
                    'symmetric key is invalid: provide RSA private key '
                    'or metadata corrupt')
            self.hmac = self._ase.encryption_metadata.initialize_hmac()
        if self.hmac is None and options.store_file_properties.md5:
            self.md5 = blobxfer.util.new_md5_hasher()

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: upload offsets
        """
        # TODO RESUME
#         resume_bytes = self._resume()
        resume_bytes = None
        with self._meta_lock:
#             if self._offset >= self._ase.size:
#                 return None, resume_bytes
            if self._offset + self._chunk_size > self._ase.size:
                chunk = self._ase.size - self._offset
            else:
                chunk = self._chunk_size
            num_bytes = chunk
            chunk_num = self._chunk_num
            fd_start = self._offset
            range_start = self._offset
            range_end = self._offset + num_bytes - 1
            self._offset += chunk
            self._chunk_num += 1
            if self._ase.is_encrypted and self._offset >= self._ase.size:
                pad = True
            else:
                pad = False
            return Offsets(
                chunk_num=chunk_num,
                block_id='{0:08d}'.format(chunk_num),
                fd_start=fd_start,
                num_bytes=chunk,
                range_start=range_start,
                range_end=range_end,
                pad=pad,
            ), resume_bytes
