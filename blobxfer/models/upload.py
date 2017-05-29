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
_MAX_BLOCK_BLOB_CHUNKSIZE_BYTES = 268435456
_MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES = 4194304
_MAX_NUM_CHUNKS = 50000
_DEFAULT_AUTO_CHUNKSIZE_BYTES = 16777216


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

    def __init__(self, parent_path, relative_path, view=None):
        # type: (LocalPath, pathlib.Path, pathlib.Path, LocalPathView) -> None
        """Ctor for LocalPath
        :param LocalPath self: this
        :param pathlib.Path parent_path: parent path
        :param pathlib.Path relative_path: relative path
        :param LocalPathView view: local path view
        """
        self.parent_path = parent_path
        self.relative_path = relative_path
        # populate properties
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
        """Check if ource can be renamed
        :param LocalSourcePath self: this
        :rtype: bool
        :return: if rename possible
        """
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
        self._store_file_attr = options.store_file_properties.attributes
        self.current_iv = None
        self._initialize_encryption(options)
        # calculate the total number of ops required for transfer
        self._compute_remote_size()
        self._adjust_chunk_size(options)
        self._total_chunks = self._compute_total_chunks(self._chunk_size)
        self._outstanding_ops = self._total_chunks
        if blobxfer.util.is_not_empty(self._ase.replica_targets):
            self._outstanding_ops *= len(self._ase.replica_targets)
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
        return self._resume_mgr is not None and self.hmac is None

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
    def is_one_shot_block_blob(self):
        # type: (Descriptor) -> bool
        """Is one shot block blob
        :param Descriptor self: this
        :rtype: bool
        :return: if upload is a one-shot block blob
        """
        return (self._ase.mode == blobxfer.models.azure.StorageModes.Block and
                self._total_chunks == 1)

    @property
    def requires_put_block_list(self):
        # type: (Descriptor) -> bool
        """Requires a put block list operation to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put block list
        """
        return (self._ase.mode == blobxfer.models.azure.StorageModes.Block and
                self._total_chunks > 1)

    @property
    def requires_non_encrypted_md5_put(self):
        # type: (Descriptor) -> bool
        """Requires a set file properties for md5 to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put file properties
        """
        return not self.entity.is_encrypted and self.must_compute_md5

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

    def complete_offset_upload(self):
        # type: (Descriptor) -> None
        """Complete the upload for the offset
        :param Descriptor self: this
        """
        with self._meta_lock:
            self._outstanding_ops -= 1
        # TODO save resume state

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
        # TODO support append blobs?
        if (options.rsa_public_key is not None and self.local_path.size > 0 and
                (self._ase.mode == blobxfer.models.azure.StorageModes.Block or
                 self._ase.mode == blobxfer.models.azure.StorageModes.File)):
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
                allocatesize = (size // self._AES_BLOCKSIZE + 1) * \
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
            logger.debug(
                'auto-selected chunk size of {} for {}'.format(
                    chunk_size, self.local_path.absolute_path))
        self._chunk_size = min((chunk_size, self._ase.size))
        # ensure chunk sizes are compatible with mode
        if self._ase.mode == blobxfer.models.azure.StorageModes.Append:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    ('adjusting chunk size to {} for append blob '
                     'from {}').format(
                         self._chunk_size, self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Block:
            if self._ase.size <= options.one_shot_bytes:
                self._chunk_size = min(
                    (self._ase.size, options.one_shot_bytes)
                )
            else:
                if self._chunk_size > _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES:
                    self._chunk_size = _MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
                    logger.debug(
                        ('adjusting chunk size to {} for block blob '
                         'from {}').format(
                            self._chunk_size, self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.File:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    'adjusting chunk size to {} for file from {}'.format(
                        self._chunk_size, self.local_path.absolute_path))
        elif self._ase.mode == blobxfer.models.azure.StorageModes.Page:
            if self._chunk_size > _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES:
                self._chunk_size = _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
                logger.debug(
                    'adjusting chunk size to {} for page blob from {}'.format(
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
        if chunks > 50000:
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
        if options.store_file_properties.md5:
            self.md5 = blobxfer.util.new_md5_hasher()

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: upload offsets
        """
        # TODO RESUME
        resume_bytes = None
#         resume_bytes = self._resume()
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
        # type: (Descriptor, Offsets) -> bytes
        """Read data from file
        :param Descriptor self: this
        :param Offsets offsets: offsets
        :rtype: bytes
        :return: file data
        """
        if offsets.num_bytes == 0:
            return None
        # compute start from view
        start = self.local_path.view.fd_start + offsets.range_start
        # encrypted offsets will read past the end of the file due
        # to padding, but will be accounted for after encryption+padding
        with self.local_path.absolute_path.open('rb') as fd:
            fd.seek(start, 0)
            data = fd.read(offsets.num_bytes)
        if self.must_compute_md5:
            with self._hasher_lock:
                self.md5.update(data)
        return data

    def generate_metadata(self):
        # type: (Descriptor) -> dict
        """Generate metadata for descriptor
        :param Descriptor self: this
        :rtype: dict or None
        :return: kv metadata dict
        """
        genmeta = {}
        encmeta = {}
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
        if self._store_file_attr:
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
