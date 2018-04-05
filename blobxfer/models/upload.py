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
import json
import logging
import math
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
import threading
# non-stdlib imports
import bitstring
# local imports
import blobxfer.models
import blobxfer.models.azure
import blobxfer.models.crypto
import blobxfer.models.metadata
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_MAX_BLOCK_BLOB_ONESHOT_BYTES = 268435456
_MAX_BLOCK_BLOB_CHUNKSIZE_BYTES = 104857600
_MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES = 4194304
_MAX_NUM_CHUNKS = 50000
_MAX_PAGE_BLOB_SIZE = 8796093022208
_DEFAULT_AUTO_CHUNKSIZE_BYTES = 16777216
_MD5_CACHE_RESUME_ENTRIES_GC_THRESHOLD = 25


# named tuples
Offsets = collections.namedtuple(
    'Offsets', [
        'chunk_num',
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
        'mode',
        'next',
        'slice_num',
        'total_slices',
    ]
)


class VectoredIoDistributionMode(enum.Enum):
    Disabled = 'disabled'
    Stripe = 'stripe'
    Replica = 'replica'

    def __str__(self):
        return self.value


class LocalPath(object):
    """Local Path"""

    def __init__(self, parent_path, relative_path, use_stdin=False, view=None):
        # type: (LocalPath, pathlib.Path, pathlib.Path, bool,
        #        LocalPathView) -> None
        """Ctor for LocalPath
        :param LocalPath self: this
        :param pathlib.Path parent_path: parent path
        :param pathlib.Path relative_path: relative path
        :param bool use_stdin: use stdin
        :param LocalPathView view: local path view
        """
        self.parent_path = parent_path
        self.relative_path = relative_path
        self.use_stdin = use_stdin
        # populate properties
        if self.use_stdin:
            # create dummy stat object
            self._stat = lambda: None
            self._stat.st_size = 0
            self._stat.st_mtime = 0
            self._stat.st_mode = 0
            self._stat.st_uid = 0
            self._stat.st_gid = 0
        else:
            self._stat = self.absolute_path.stat()
        if view is None:
            self.view = LocalPathView(
                fd_start=0,
                fd_end=self._stat.st_size,
                slice_num=0,
                mode=VectoredIoDistributionMode.Disabled,
                total_slices=1,
                next=None,
            )
        else:
            self.view = view
        self._size = self.view.fd_end - self.view.fd_start

    @property
    def absolute_path(self):
        # type: (LocalPath) -> pathlib.Path
        """Absolute path
        :param LocalPath self: this
        :rtype: pathlib.Path
        :return: absolute path
        """
        return self.parent_path / self.relative_path

    @property
    def size(self):
        # type: (LocalPath) -> int
        """Size of view
        :param LocalPath self: this
        :rtype: int
        :return: size of view portion of the file
        """
        return self._size

    @property
    def total_size(self):
        # type: (LocalPath) -> int
        """Total Size of file
        :param LocalPath self: this
        :rtype: int
        :return: total size of file (non-view)
        """
        return self._stat.st_size

    @property
    def lmt(self):
        # type: (LocalPath) -> int
        """mtime of file
        :param LocalPath self: this
        :rtype: int
        :return: mtime of file
        """
        return self._stat.st_mtime

    @property
    def mode(self):
        # type: (LocalPath) -> str
        """Octal file mode
        :param LocalPath self: this
        :rtype: str
        :return: octal file mode
        """
        return str(oct(self._stat.st_mode))

    @property
    def uid(self):
        # type: (LocalPath) -> int
        """Uid of file
        :param LocalPath self: this
        :rtype: int
        :return: uid of file
        """
        return self._stat.st_uid

    @property
    def gid(self):
        # type: (LocalPath) -> int
        """Gid of file
        :param LocalPath self: this
        :rtype: int
        :return: gid of file
        """
        return self._stat.st_gid


class LocalSourcePath(blobxfer.models._BaseSourcePaths):
    """Local Source Path"""

    def can_rename(self):
        # type: (LocalSourcePaths) -> bool
        """Check if source can be renamed
        :param LocalSourcePath self: this
        :rtype: bool
        :return: if rename possible
        """
        return len(self._paths) == 1 and (
            self._paths[0].is_file() or
            blobxfer.models.upload.LocalSourcePath.is_stdin(
                str(self._paths[0]))
        )

    @staticmethod
    def is_stdin(path):
        # type: (str) -> bool
        """Check if path is stdin
        :param str path: path to check
        :rtype: bool
        :return: if path is stdin
        """
        if path == '-' or path == '/dev/stdin':
            return True
        return False

    def files(self):
        # type: (LocalSourcePaths) -> LocalPath
        """Generator for files in paths
        :param LocalSourcePath self: this
        :rtype: LocalPath
        :return: LocalPath
        """
        for _path in self._paths:
            _ppath = os.path.expandvars(os.path.expanduser(str(_path)))
            # check of path is stdin
            if blobxfer.models.upload.LocalSourcePath.is_stdin(_ppath):
                yield LocalPath(
                    parent_path=pathlib.Path(),
                    relative_path=pathlib.Path('stdin'),
                    use_stdin=True,
                )
                continue
            # resolve path
            _expath = pathlib.Path(_ppath).resolve()
            # check if path is a single file
            tmp = pathlib.Path(_ppath)
            if tmp.is_file():
                if self._inclusion_check(tmp.name):
                    yield LocalPath(
                        parent_path=tmp.parent,
                        relative_path=pathlib.Path(tmp.name),
                        use_stdin=False,
                    )
            else:
                del tmp
                for entry in blobxfer.util.scantree(_ppath):
                    _rpath = pathlib.Path(entry.path).relative_to(_ppath)
                    if not self._inclusion_check(_rpath):
                        continue
                    yield LocalPath(
                        parent_path=_expath,
                        relative_path=_rpath,
                        use_stdin=False,
                    )


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
        if self.options.chunk_size_bytes < 0:
            raise ValueError('chunk size cannot be negative')
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

    def __init__(self, lpath, ase, uid, options, general_options, resume_mgr):
        # type: (Descriptior, LocalPath,
        #        blobxfer.models.azure.StorageEntity, str,
        #        blobxfer.models.options.Upload,
        #        blobxfer.models.options.General,
        #        blobxfer.operations.resume.UploadResumeManager) -> None
        """Ctor for Descriptor
        :param Descriptor self: this
        :param LocalPath lpath: local path
        :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
        :param str uid: unique id
        :param blobxfer.models.options.Upload options: download options
        :param blobxfer.models.options.General general_options: general options
        :param blobxfer.operations.resume.UploadResumeManager resume_mgr:
            upload resume manager
        """
        self.local_path = lpath
        self.unique_id = uid
        self._verbose = general_options.verbose
        self._offset = 0
        self._chunk_num = 0
        self._next_integrity_chunk = 0
        self._finalized = False
        self._needs_resize = False
        self._meta_lock = threading.Lock()
        self._hasher_lock = threading.Lock()
        if resume_mgr and self.local_path.use_stdin:
            logger.warning('ignoring resume option for stdin source')
            self._resume_mgr = None
        else:
            self._resume_mgr = resume_mgr
        self._ase = ase
        self._store_file_attr = options.store_file_properties.attributes
        self.current_iv = None
        self._initialize_encryption(options)
        # calculate the total number of ops required for transfer
        self._compute_remote_size(options)
        self._adjust_chunk_size(options)
        self._total_chunks = self._compute_total_chunks(self._chunk_size)
        self._outstanding_ops = self._total_chunks
        if blobxfer.util.is_not_empty(self._ase.replica_targets):
            self._outstanding_ops *= len(self._ase.replica_targets) + 1
        if self._resume_mgr:
            self._completed_chunks = bitstring.BitArray(
                length=self._total_chunks)
            self._md5_cache = {}
            self._replica_counters = {}
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
            return self._outstanding_ops == 0

    @property
    def last_block_num(self):
        # type: (Descriptor) -> bool
        """Last used block number for block id, should only be called for
        finalize operation
        :param Descriptor self: this
        :rtype: int
        :return: block number
        """
        with self._meta_lock:
            return self._chunk_num - 1

    @property
    def is_resumable(self):
        # type: (Descriptor) -> bool
        """Upload is resume capable
        :param Descriptor self: this
        :rtype: bool
        :return: if resumable
        """
        return (self._resume_mgr is not None and self.hmac is None and
                not self.remote_is_append_blob)

    @property
    def remote_is_file(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure File
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure File
        """
        return self.entity.mode == blobxfer.models.azure.StorageModes.File

    @property
    def remote_is_page_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Page Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Page Blob
        """
        return self.entity.mode == blobxfer.models.azure.StorageModes.Page

    @property
    def remote_is_append_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Append Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Append Blob
        """
        return self.entity.mode == blobxfer.models.azure.StorageModes.Append

    @property
    def remote_is_block_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Block Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Block Blob
        """
        return self.entity.mode == blobxfer.models.azure.StorageModes.Block

    @property
    def is_one_shot_block_blob(self):
        # type: (Descriptor) -> bool
        """Is one shot block blob
        :param Descriptor self: this
        :rtype: bool
        :return: if upload is a one-shot block blob
        """
        return self.remote_is_block_blob and self._total_chunks == 1

    @property
    def requires_put_block_list(self):
        # type: (Descriptor) -> bool
        """Requires a put block list operation to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put block list
        """
        return self.remote_is_block_blob and self._total_chunks > 1

    @property
    def requires_non_encrypted_md5_put(self):
        # type: (Descriptor) -> bool
        """Requires a set file properties for md5 to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put file properties
        """
        return (not self.entity.is_encrypted and self.must_compute_md5 and
                not self.remote_is_append_blob)

    @property
    def requires_set_file_properties_md5(self):
        # type: (Descriptor) -> bool
        """Requires a set file properties for md5 to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put file properties
        """
        return (not self.entity.is_encrypted and self.must_compute_md5 and
                self.remote_is_file)

    @property
    def requires_access_tier_set(self):
        # type: (Descriptor) -> bool
        """Remote destination requires an access tier set operation
        :param Descriptor self: this
        :rtype: bool
        :return: access tier is set
        """
        return (self.remote_is_block_blob and
                self.entity.access_tier is not None)

    def requires_resize(self):
        # type: (Descriptor) -> tuple
        """Remote destination requires a resize operation
        :param Descriptor self: this
        :rtype: tuple
        :return: blob requires a resize, length
        """
        with self._meta_lock:
            return (self._needs_resize, self._offset)

    def complete_offset_upload(self, chunk_num):
        # type: (Descriptor, int) -> None
        """Complete the upload for the offset
        :param Descriptor self: this
        :param int chunk_num: chunk num completed
        """
        with self._meta_lock:
            self._outstanding_ops -= 1
            # save resume state
            if self.is_resumable:
                # only set resumable completed if all replicas for this
                # chunk are complete
                if blobxfer.util.is_not_empty(self._ase.replica_targets):
                    if chunk_num not in self._replica_counters:
                        # start counter at -1 since we need 1 "extra" for the
                        # primary in addition to the replica targets
                        self._replica_counters[chunk_num] = -1
                    self._replica_counters[chunk_num] += 1
                    if (self._replica_counters[chunk_num] !=
                            len(self._ase.replica_targets)):
                        return
                    else:
                        self._replica_counters.pop(chunk_num)
                self._completed_chunks.set(True, chunk_num)
                completed = self._outstanding_ops == 0
                if not completed and self.must_compute_md5:
                    last_consecutive = (
                        self._completed_chunks.find('0b0')[0] - 1
                    )
                    md5digest = self._md5_cache[last_consecutive]
                else:
                    md5digest = None
                self._resume_mgr.add_or_update_record(
                    self.local_path.absolute_path, self._ase, self._chunk_size,
                    self._total_chunks, self._completed_chunks.int, completed,
                    md5digest,
                )
                # prune md5 cache
                if self.must_compute_md5:
                    if completed:
                        self._md5_cache.clear()
                    elif (len(self._md5_cache) >
                          _MD5_CACHE_RESUME_ENTRIES_GC_THRESHOLD):
                        mkeys = sorted(list(self._md5_cache.keys()))
                        for key in mkeys:
                            if key >= last_consecutive:
                                break
                            self._md5_cache.pop(key)

    def hmac_data(self, data):
        # type: (Descriptor, bytes) -> None
        """Send data through hmac hasher
        :param Descriptor self: this
        :param bytes data: data
        """
        with self._hasher_lock:
            self.hmac.update(data)

    def _initialize_encryption(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Download is resume capable
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        """
        if (options.rsa_public_key is not None and self.local_path.size > 0 and
                (self._ase.mode == blobxfer.models.azure.StorageModes.Block or
                 self._ase.mode == blobxfer.models.azure.StorageModes.File)):
            em = blobxfer.models.crypto.EncryptionMetadata()
            em.create_new_metadata(options.rsa_public_key)
            self.current_iv = em.content_encryption_iv
            self._ase.encryption_metadata = em

    def _compute_remote_size(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Compute total remote file size
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        :rtype: int
        :return: remote file size
        """
        size = self.local_path.size
        if (self._ase.mode == blobxfer.models.azure.StorageModes.Page and
                self.local_path.use_stdin):
            if options.stdin_as_page_blob_size == 0:
                allocatesize = _MAX_PAGE_BLOB_SIZE
                self._needs_resize = True
            else:
                allocatesize = options.stdin_as_page_blob_size
        elif size > 0:
            if self._ase.is_encrypted:
                # cipher_len_without_iv = (clear_len / aes_bs + 1) * aes_bs
                allocatesize = (size // self._AES_BLOCKSIZE + 1) * \
                    self._AES_BLOCKSIZE
            else:
                allocatesize = size
        else:
            allocatesize = 0
        self._ase.size = allocatesize
        if blobxfer.util.is_not_empty(self._ase.replica_targets):
            for rt in self._ase.replica_targets:
                rt.size = allocatesize
        if self._verbose:
            logger.debug('remote size for {} is {} bytes'.format(
                self._ase.path, self._ase.size))

    def _adjust_chunk_size(self, options):
        # type: (Descriptor, blobxfer.models.options.Upload) -> None
        """Adjust chunk size for entity mode
        :param Descriptor self: this
        :param blobxfer.models.options.Upload options: upload options
        """
        chunk_size = options.chunk_size_bytes
        # auto-select chunk size
        if chunk_size == 0:
            if self._ase.mode != blobxfer.models.azure.StorageModes.Block:
                chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
            else:
                if self._ase.size == 0:
                    chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                else:
                    chunk_size = _DEFAULT_AUTO_CHUNKSIZE_BYTES
                    while chunk_size < _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
                        chunks = int(math.ceil(self._ase.size / chunk_size))
                        if chunks <= _MAX_NUM_CHUNKS:
                            break
                        chunk_size = chunk_size << 1
            if self._verbose:
                logger.debug(
                    'auto-selected chunk size of {} for {}'.format(
                        chunk_size, self.local_path.absolute_path))
        if self.local_path.use_stdin:
            self._chunk_size = max(
                (chunk_size, _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES)
            )
        else:
            self._chunk_size = min((chunk_size, self._ase.size))
        # ensure chunk sizes are compatible with mode
        if self._ase.mode == blobxfer.models.azure.StorageModes.Append:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                if self._verbose:
                    logger.debug(
                        ('adjusting chunk size to {} for append blob '
                         'from {}').format(
                             self._chunk_size, self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Block:
            if (not self.local_path.use_stdin and
                    self._ase.size <= options.one_shot_bytes):
                self._chunk_size = min(
                    (self._ase.size, options.one_shot_bytes)
                )
            else:
                if self._chunk_size > _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
                    self._chunk_size = _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
                    if self._verbose:
                        logger.debug(
                            ('adjusting chunk size to {} for block blob '
                             'from {}').format(
                                self._chunk_size,
                                 self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.File:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                if self._verbose:
                    logger.debug(
                        'adjusting chunk size to {} for file from {}'.format(
                            self._chunk_size, self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Page:
            if self._ase.size > _MAX_PAGE_BLOB_SIZE:
                raise RuntimeError(
                    '{} size {} exceeds maximum page blob size of {}'.format(
                        self.local_path.absolute_path, self._ase.size,
                        _MAX_PAGE_BLOB_SIZE))
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                if self._verbose:
                    logger.debug(
                        ('adjusting chunk size to {} for page blob '
                         'from {}').format(
                             self._chunk_size, self.local_path.absolute_path))

    def _compute_total_chunks(self, chunk_size):
        # type: (Descriptor, int) -> int
        """Compute total number of chunks for entity
        :param Descriptor self: this
        :param int chunk_size: chunk size
        :rtype: int
        :return: num chunks
        """
        try:
            chunks = int(math.ceil(self._ase.size / chunk_size))
        except ZeroDivisionError:
            chunks = 1
        # for stdin, override and use 1 chunk to start, this will change
        # dynamically as data as read
        if self.local_path.use_stdin:
            chunks = 1
        if (self._ase.mode != blobxfer.models.azure.StorageModes.Page and
                chunks > 50000):
            max_vector = False
            if self._ase.mode == blobxfer.models.azure.StorageModes.Block:
                if self._chunk_size == _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
                    max_vector = True
            elif self._chunk_size == _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                max_vector = True
            if max_vector:
                raise RuntimeError(
                    ('number of chunks {} exceeds maximum permissible '
                     'limit and chunk size is set at the maximum value '
                     'for {}. Please try using stripe mode '
                     'vectorization to overcome this limitation').format(
                        chunks, self.local_path.absolute_path))
            else:
                raise RuntimeError(
                    ('number of chunks {} exceeds maximum permissible '
                     'limit for {}, please adjust chunk size higher or '
                     'set to -1 for automatic chunk size selection').format(
                         chunks, self.local_path.absolute_path))
        return chunks

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
                    ('symmetric key is invalid: provide RSA private key '
                     'or metadata corrupt for {}').format(
                         self.local_path.absolute_path))
            self.hmac = self._ase.encryption_metadata.initialize_hmac()
        # both hmac and md5 can be enabled
        if (options.store_file_properties.md5 and
                not self.remote_is_append_blob):
            self.md5 = blobxfer.util.new_md5_hasher()

    def _resume(self):
        # type: (Descriptor) -> int
        """Resume upload
        :param Descriptor self: this
        :rtype: int
        :return: resume bytes
        """
        if self._resume_mgr is None or self._offset > 0:
            return None
        # check if path exists in resume db
        rr = self._resume_mgr.get_record(self._ase)
        if rr is None:
            logger.debug('no resume record for {}'.format(self._ase.path))
            return None
        # ensure lengths are the same
        if rr.length != self._ase.size:
            logger.warning('resume length mismatch {} -> {}'.format(
                rr.length, self._ase.size))
            return None
        # compute replica factor
        if blobxfer.util.is_not_empty(self._ase.replica_targets):
            replica_factor = 1 + len(self._ase.replica_targets)
        else:
            replica_factor = 1
        # set offsets if completed
        if rr.completed:
            with self._meta_lock:
                logger.debug('{} upload already completed'.format(
                    self._ase.path))
                self._offset = rr.total_chunks * rr.chunk_size
                self._chunk_num = rr.total_chunks
                self._chunk_size = rr.chunk_size
                self._total_chunks = rr.total_chunks
                self._completed_chunks.int = rr.completed_chunks
                self._outstanding_ops = 0
                return self._ase.size * replica_factor
        # encrypted files are not resumable due to hmac requirement
        if self._ase.is_encrypted:
            logger.debug('cannot resume encrypted entity {}'.format(
                self._ase.path))
            return None
        # check if path exists
        if not pathlib.Path(rr.local_path).exists():
            logger.warning('resume from local path {} does not exist'.format(
                rr.local_path))
            return None
        # re-hash from 0 to offset if needed
        _cc = bitstring.BitArray(length=rr.total_chunks)
        _cc.int = rr.completed_chunks
        curr_chunk = _cc.find('0b0')[0]
        del _cc
        _fd_offset = 0
        _end_offset = min((curr_chunk * rr.chunk_size, rr.length))
        if self.md5 is not None and curr_chunk > 0:
            _blocksize = blobxfer.util.MEGABYTE << 2
            logger.debug(
                'integrity checking existing file {} offset {} -> {}'.format(
                    self._ase.path,
                    self.local_path.view.fd_start,
                    self.local_path.view.fd_start + _end_offset)
            )
            with self._hasher_lock:
                with self.local_path.absolute_path.open('rb') as filedesc:
                    filedesc.seek(self.local_path.view.fd_start, 0)
                    while _fd_offset < _end_offset:
                        if (_fd_offset + _blocksize) > _end_offset:
                            _blocksize = _end_offset - _fd_offset
                        _buf = filedesc.read(_blocksize)
                        self.md5.update(_buf)
                        _fd_offset += _blocksize
            del _blocksize
            # compare hashes
            hexdigest = self.md5.hexdigest()
            if rr.md5hexdigest != hexdigest:
                logger.warning(
                    'MD5 mismatch resume={} computed={} for {}'.format(
                        rr.md5hexdigest, hexdigest, self._ase.path))
                # reset hasher
                self.md5 = blobxfer.util.new_md5_hasher()
                return None
        # set values from resume
        with self._meta_lock:
            self._offset = _end_offset
            self._chunk_num = curr_chunk
            self._chunk_size = rr.chunk_size
            self._total_chunks = rr.total_chunks
            self._completed_chunks = bitstring.BitArray(length=rr.total_chunks)
            self._completed_chunks.set(True, range(0, curr_chunk + 1))
            self._outstanding_ops = (
                (rr.total_chunks - curr_chunk) * replica_factor
            )
            logger.debug(
                ('resuming file {} from byte={} chunk={} chunk_size={} '
                 'total_chunks={} outstanding_ops={}').format(
                     self._ase.path, self._offset, self._chunk_num,
                     self._chunk_size, self._total_chunks,
                     self._outstanding_ops))
            return _end_offset * replica_factor

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: upload offsets
        """
        resume_bytes = self._resume()
        with self._meta_lock:
            if self._chunk_num >= self._total_chunks:
                return None, resume_bytes
            if self._offset + self._chunk_size > self._ase.size:
                num_bytes = self._ase.size - self._offset
            else:
                num_bytes = self._chunk_size
            chunk_num = self._chunk_num
            range_start = self._offset
            range_end = self._offset + num_bytes - 1
            self._offset += num_bytes
            self._chunk_num += 1
            if self._ase.is_encrypted and self._offset >= self._ase.size:
                pad = True
            else:
                pad = False
            return Offsets(
                chunk_num=chunk_num,
                num_bytes=num_bytes,
                range_start=range_start,
                range_end=range_end,
                pad=pad,
            ), resume_bytes

    def read_data(self, offsets):
        # type: (Descriptor, Offsets) -> Tuple[bytes, Offsets]
        """Read data from file
        :param Descriptor self: this
        :param Offsets offsets: offsets
        :rtype: tuple
        :return: (file data bytes, new Offsets if stdin)
        """
        newoffset = None
        if not self.local_path.use_stdin:
            if offsets.num_bytes == 0:
                return None, None
            # compute start from view
            start = self.local_path.view.fd_start + offsets.range_start
            # encrypted offsets will read past the end of the file due
            # to padding, but will be accounted for after encryption+padding
            with self.local_path.absolute_path.open('rb') as fd:
                fd.seek(start, 0)
                data = fd.read(offsets.num_bytes)
        else:
            data = blobxfer.STDIN.read(self._chunk_size)
            if not data:
                with self._meta_lock:
                    self._offset -= offsets.num_bytes
                    self._ase.size -= offsets.num_bytes
                    self._total_chunks -= 1
                    self._chunk_num -= 1
                    self._outstanding_ops -= 1
            else:
                num_bytes = len(data)
                with self._meta_lock:
                    self._offset -= offsets.num_bytes
                    self._ase.size -= offsets.num_bytes
                    newoffset = Offsets(
                        chunk_num=self._chunk_num - 1,
                        num_bytes=num_bytes,
                        range_start=self._offset,
                        range_end=self._offset + num_bytes - 1,
                        pad=False,
                    )
                    self._total_chunks += 1
                    self._outstanding_ops += 1
                    self._offset += num_bytes
                    self._ase.size += num_bytes
        if self.must_compute_md5 and data:
            with self._hasher_lock:
                self.md5.update(data)
                if self.is_resumable:
                    self._md5_cache[self._chunk_num - 1] = self.md5.hexdigest()
        return data, newoffset

    def generate_metadata(self):
        # type: (Descriptor) -> dict
        """Generate metadata for descriptor
        :param Descriptor self: this
        :rtype: dict or None
        :return: kv metadata dict
        """
        genmeta = {}
        encmeta = {}
        # page align md5
        if (self.must_compute_md5 and
                self._ase.mode == blobxfer.models.azure.StorageModes.Page):
            aligned = blobxfer.util.page_align_content_length(self._offset)
            diff = aligned - self._offset
            if diff > 0:
                with self._hasher_lock:
                    self.md5.update(b'\0' * diff)
        # generate encryption metadata
        if self._ase.is_encrypted:
            if self.must_compute_md5:
                md5digest = blobxfer.util.base64_encode_as_string(
                    self.md5.digest())
            else:
                md5digest = None
            if self.hmac is not None:
                hmacdigest = blobxfer.util.base64_encode_as_string(
                    self.hmac.digest())
            else:
                hmacdigest = None
            encmeta = self._ase.encryption_metadata.convert_to_json_with_mac(
                md5digest, hmacdigest)
        # generate file attribute metadata
        if self._store_file_attr and not self.local_path.use_stdin:
            merged = blobxfer.models.metadata.generate_fileattr_metadata(
                self.local_path, genmeta)
            if merged is not None:
                genmeta = merged
        # generate vectored io metadata
        if self.local_path.view.mode == VectoredIoDistributionMode.Stripe:
            merged = blobxfer.models.metadata.\
                generate_vectored_io_stripe_metadata(self.local_path, genmeta)
            if merged is not None:
                genmeta = merged
        if len(encmeta) > 0:
            metadata = encmeta
        else:
            metadata = {}
        if len(genmeta) > 0:
            metadata[blobxfer.models.metadata.JSON_KEY_BLOBXFER_METADATA] = \
                json.dumps(genmeta, ensure_ascii=False, sort_keys=True)
        if len(metadata) == 0:
            return None
        return metadata
