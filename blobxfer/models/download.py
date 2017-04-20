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
import logging
import math
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
import tempfile
import threading
# non-stdlib imports
# local imports
import blobxfer.models.azure
import blobxfer.models.crypto
import blobxfer.models.options
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)

# named tuples
Offsets = collections.namedtuple(
    'Offsets', [
        'chunk_num',
        'fd_start',
        'num_bytes',
        'range_end',
        'range_start',
        'unpad',
    ]
)
UncheckedChunk = collections.namedtuple(
    'UncheckedChunk', [
        'data_len',
        'fd_start',
        'file_path',
        'temp',
    ]
)


class LocalDestinationPath(object):
    """Local Destination Path"""
    def __init__(self, path=None):
        # type: (LocalDestinationPath, str) -> None
        """Ctor for LocalDestinationPath
        :param LocalDestinationPath self: this
        :param str path: path
        """
        self._is_dir = None
        if path is not None:
            self.path = path

    @property
    def path(self):
        # type: (LocalDestinationPath) -> pathlib.Path
        """Path property
        :param LocalDestinationPath self: this
        :rtype: pathlib.Path
        :return: local destination path
        """
        return self._path

    @path.setter
    def path(self, value):
        # type: (LocalDestinationPath, str) -> None
        """Path property setter
        :param LocalDestinationPath self: this
        :param str value: value to set path to
        """
        self._path = pathlib.Path(value)

    @property
    def is_dir(self):
        # type: (LocalDestinationPath) -> bool
        """is_dir property
        :param LocalDestinationPath self: this
        :rtype: bool
        :return: if local destination path is a directory
        """
        return self._is_dir

    @is_dir.setter
    def is_dir(self, value):
        # type: (LocalDestinationPath, bool) -> None
        """is_dir property setter
        :param LocalDestinationPath self: this
        :param bool value: value to set is_dir to
        """
        self._is_dir = value

    def ensure_path_exists(self):
        # type: (LocalDestinationPath) -> None
        """Ensure path exists
        :param LocalDestinationPath self: this
        """
        if self._is_dir is None:
            raise RuntimeError('is_dir not set')
        if self._is_dir:
            self._path.mkdir(mode=0o750, parents=True, exist_ok=True)
        else:
            if self._path.exists() and self._path.is_dir():
                raise RuntimeError(
                    ('destination path {} already exists and is a '
                     'directory').format(self._path))
            else:
                # ensure parent path exists and is created
                self._path.parent.mkdir(
                    mode=0o750, parents=True, exist_ok=True)


class Specification(object):
    """Download Specification"""
    def __init__(
            self, download_options, skip_on_options, local_destination_path):
        # type: (Specification, blobxfer.models.options.Download,
        #        blobxfer.models.options.SkipOn, LocalDestinationPath) -> None
        """Ctor for Specification
        :param DownloadSpecification self: this
        :param blobxfer.models.options.Download download_options:
            download options
        :param blobxfer.models.options.SkipOn skip_on_options: skip on options
        :param LocalDestinationPath local_destination_path: local dest path
        """
        self.options = download_options
        self.skip_on = skip_on_options
        self.destination = local_destination_path
        self.sources = []

    def add_azure_source_path(self, source):
        # type: (Specification, AzureSourcePath) -> None
        """Add an Azure Source Path
        :param DownloadSpecification self: this
        :param AzureSourcePath source: Azure source path to add
        """
        self.sources.append(source)


class Descriptor(object):
    """Download Descriptor"""

    _AES_BLOCKSIZE = blobxfer.models.crypto.AES256_BLOCKSIZE_BYTES

    def __init__(self, lpath, ase, options, resume_mgr):
        # type: (DownloadDescriptior, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.options.Download,
        #        blobxfer.operations.resume.DownloadResumeManager) -> None
        """Ctor for Descriptor
        :param Descriptor self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
        :param blobxfer.models.options.Download options: download options
        :param blobxfer.operations.resume.DownloadResumeManager resume_mgr:
            download resume manager
        """
        self._offset = 0
        self._chunk_num = 0
        self._next_integrity_chunk = 0
        self._unchecked_chunks = {}
        self._allocated = False
        self._finalized = False
        self._meta_lock = threading.Lock()
        self._hasher_lock = threading.Lock()
        self._resume_mgr = resume_mgr
        self._ase = ase
        # set paths
        self.final_path = lpath
        # create path holding the temporary file to download to
        _tmp = list(lpath.parts[:-1])
        _tmp.append(lpath.name + '.bxtmp')
        self.local_path = pathlib.Path(*_tmp)
        del _tmp
        # calculate the total number of ops required for transfer
        self._chunk_size = min((options.chunk_size_bytes, self._ase.size))
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
        """Download is resume capable
        :param Descriptor self: this
        :rtype: bool
        :return: if resumable
        """
        return self._resume_mgr is not None and self.hmac is None

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
        # type: (Descriptor, blobxfer.models.options.Download) -> None
        """Initialize file integrity checkers
        :param Descriptor self: this
        :param blobxfer.models.options.Download options: download options
        """
        if self._ase.is_encrypted:
            # ensure symmetric key exists
            if blobxfer.util.is_none_or_empty(
                    self._ase.encryption_metadata.symmetric_key):
                raise RuntimeError(
                    'symmetric key is invalid: provide RSA private key '
                    'or metadata corrupt')
            self.hmac = self._ase.encryption_metadata.initialize_hmac()
        if (self.hmac is None and options.check_file_md5 and
                blobxfer.util.is_not_empty(self._ase.md5)):
            self.md5 = blobxfer.util.new_md5_hasher()

    def _allocate_disk_space(self):
        # type: (Descriptor, int) -> None
        """Perform file allocation (possibly sparse)
        :param Descriptor self: this
        :param int size: size
        """
        with self._meta_lock:
            if self._allocated:
                return
            size = self._ase.size
            # compute size
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
            # check if path already exists and is of sufficient size
            if (not self.local_path.exists() or
                    self.local_path.stat().st_size != allocatesize):
                # create parent path
                self.local_path.parent.mkdir(
                    mode=0o750, parents=True, exist_ok=True)
                # allocate file
                with self.local_path.open('wb') as fd:
                    if allocatesize > 0:
                        try:
                            os.posix_fallocate(fd.fileno(), 0, allocatesize)
                        except AttributeError:
                            fd.seek(allocatesize - 1)
                            fd.write(b'\0')
            self._allocated = True

    def _resume(self):
        # type: (Descriptor) -> int
        """Resume a download, if possible
        :param Descriptor self: this
        :rtype: int or None
        :return: verified download offset
        """
        if self._resume_mgr is None or self._offset > 0 or self._finalized:
            return None
        # check if path exists in resume db
        rr = self._resume_mgr.get_record(str(self.final_path))
        if rr is None:
            logger.debug('no resume record for {}'.format(self.final_path))
            return None
        # ensure lengths are the same
        if rr.length != self._ase.size:
            logger.warning('resume length mismatch {} -> {}'.format(
                rr.length, self._ase.size))
            return None
        # calculate current chunk and offset
        if rr.next_integrity_chunk == 0:
            logger.debug('nothing to resume for {}'.format(self.final_path))
            return None
        curr_chunk = rr.next_integrity_chunk
        # set offsets if completed and the final path exists
        if rr.completed and self.final_path.exists():
            with self._meta_lock:
                logger.debug('{} download already completed'.format(
                    self.final_path))
                self._offset = self._ase.size
                self._chunk_num = curr_chunk
                self._chunk_size = rr.chunk_size
                self._total_chunks = self._compute_total_chunks(rr.chunk_size)
                self._next_integrity_chunk = rr.next_integrity_chunk
                self._outstanding_ops = 0
                self._finalized = True
            return self._ase.size
        # encrypted files are not resumable due to hmac requirement
        if self._ase.is_encrypted:
            logger.debug('cannot resume encrypted entity {}/{}'.format(
                self._ase.container, self._ase.name))
            return None
        # check if intermediate (blobtmp) exists
        if not self.local_path.exists():
            logger.warning('temporary download file {} does not exist'.format(
                rr.temp_path))
            return None
        if self.hmac is not None:
            raise RuntimeError(
                'unexpected hmac object for entity {}/{}'.format(
                    self._ase.container, self._ase.name))
        # re-hash from 0 to offset if needed
        _fd_offset = 0
        _end_offset = min((curr_chunk * rr.chunk_size, rr.length))
        if self.md5 is not None and curr_chunk > 0:
            _blocksize = blobxfer.util.MEGABYTE << 2
            logger.debug(
                'integrity checking existing file {} to offset {}'.format(
                    self.final_path, _end_offset))
            with self._hasher_lock:
                with self.local_path.open('rb') as filedesc:
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
                         rr.md5hexdigest, hexdigest, self.local_path))
                # reset hasher
                self.md5 = blobxfer.util.new_md5_hasher()
                return None
        # set values from resume
        with self._meta_lock:
            self._offset = _end_offset
            self._chunk_num = curr_chunk
            self._chunk_size = rr.chunk_size
            self._total_chunks = self._compute_total_chunks(rr.chunk_size)
            self._next_integrity_chunk = rr.next_integrity_chunk
            self._outstanding_ops = (
                self._total_chunks - self._next_integrity_chunk
            )
            logger.debug(
                ('resuming file {} from byte={} chunk={} chunk_size={} '
                 'total_chunks={} next_integrity_chunk={} '
                 'outstanding_ops={}').format(
                     self.final_path, self._offset, self._chunk_num,
                     self._chunk_size, self._total_chunks,
                     self._next_integrity_chunk, self._outstanding_ops))
        return _end_offset

    def cleanup_all_temporary_files(self):
        # type: (Descriptor) -> None
        """Cleanup all temporary files in case of an exception or interrupt.
        This function is not thread-safe.
        :param Descriptor self: this
        """
        # delete local file
        try:
            self.local_path.unlink()
        except OSError:
            pass
        # iterate unchecked chunks and delete
        for key in self._unchecked_chunks:
            ucc = self._unchecked_chunks[key]
            if ucc.temp:
                try:
                    ucc.file_path.unlink()
                except OSError:
                    pass

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: download offsets
        """
        resume_bytes = self._resume()
        if resume_bytes is None and not self._allocated:
            self._allocate_disk_space()
        with self._meta_lock:
            if self._offset >= self._ase.size:
                return None, resume_bytes
            if self._offset + self._chunk_size > self._ase.size:
                chunk = self._ase.size - self._offset
            else:
                chunk = self._chunk_size
            # on download, num_bytes must be offset by -1 as the x-ms-range
            # header expects it that way. x -> y bytes means first bits of the
            # (x+1)th byte to the last bits of the (y+1)th byte. for example,
            # 0 -> 511 means byte 1 to byte 512
            num_bytes = chunk - 1
            chunk_num = self._chunk_num
            fd_start = self._offset
            range_start = self._offset
            if self._ase.is_encrypted:
                # ensure start is AES block size aligned
                range_start = range_start - \
                    (range_start % self._AES_BLOCKSIZE) - \
                    self._AES_BLOCKSIZE
                if range_start <= 0:
                    range_start = 0
            range_end = self._offset + num_bytes
            self._offset += chunk
            self._chunk_num += 1
            if self._ase.is_encrypted and self._offset >= self._ase.size:
                unpad = True
            else:
                unpad = False
            return Offsets(
                chunk_num=chunk_num,
                fd_start=fd_start,
                num_bytes=chunk,
                range_start=range_start,
                range_end=range_end,
                unpad=unpad,
            ), resume_bytes

    def hmac_iv(self, iv):
        # type: (Descriptor, bytes) -> None
        """Send IV through hasher
        :param Descriptor self: this
        :param bytes iv: iv
        """
        with self._hasher_lock:
            self.hmac.update(iv)

    def write_unchecked_data(self, offsets, data):
        # type: (Descriptor, Offsets, bytes) -> None
        """Write unchecked data to disk
        :param Descriptor self: this
        :param Offsets offsets: download offsets
        :param bytes data: data
        """
        with self.local_path.open('r+b') as fd:
            fd.seek(offsets.fd_start, 0)
            fd.write(data)
        unchecked = UncheckedChunk(
            data_len=len(data),
            fd_start=offsets.fd_start,
            file_path=self.local_path,
            temp=False,
        )
        with self._meta_lock:
            self._unchecked_chunks[offsets.chunk_num] = unchecked

    def write_unchecked_hmac_data(self, offsets, data):
        # type: (Descriptor, Offsets, bytes) -> None
        """Write unchecked encrypted data to disk
        :param Descriptor self: this
        :param Offsets offsets: download offsets
        :param bytes data: hmac/encrypted data
        """
        fname = None
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as fd:
            fname = fd.name
            fd.write(data)
        unchecked = UncheckedChunk(
            data_len=len(data),
            fd_start=0,
            file_path=pathlib.Path(fname),
            temp=True,
        )
        with self._meta_lock:
            self._unchecked_chunks[offsets.chunk_num] = unchecked
        return str(unchecked.file_path)

    def perform_chunked_integrity_check(self):
        # type: (Descriptor) -> None
        """Hash data against stored hasher safely
        :param Descriptor self: this
        """
        hasher = self.hmac or self.md5
        # iterate from next chunk to be checked
        while True:
            ucc = None
            with self._meta_lock:
                chunk_num = self._next_integrity_chunk
                # check if the next chunk is ready
                if chunk_num in self._unchecked_chunks:
                    ucc = self._unchecked_chunks.pop(chunk_num)
                else:
                    break
            # hash data and set next integrity chunk
            md5hexdigest = None
            if hasher is not None:
                with ucc.file_path.open('rb') as fd:
                    if not ucc.temp:
                        fd.seek(ucc.fd_start, 0)
                    chunk = fd.read(ucc.data_len)
                if ucc.temp:
                    ucc.file_path.unlink()
                with self._hasher_lock:
                    hasher.update(chunk)
                    if hasher == self.md5:
                        md5hexdigest = hasher.hexdigest()
            with self._meta_lock:
                # update integrity counter and resume db
                self._next_integrity_chunk += 1
                if self.is_resumable:
                    self._resume_mgr.add_or_update_record(
                        self.final_path, self.local_path, self._ase.size,
                        self._chunk_size, self._next_integrity_chunk, False,
                        md5hexdigest,
                    )
                # decrement outstanding op counter
                self._outstanding_ops -= 1

    def _update_resume_for_completed(self):
        # type: (Descriptor) -> None
        """Update resume for completion
        :param Descriptor self: this
        """
        if not self.is_resumable:
            return
        with self._meta_lock:
            self._resume_mgr.add_or_update_record(
                self.final_path, self.local_path, self._ase.size,
                self._chunk_size, self._next_integrity_chunk, True, None,
            )

    def write_data(self, offsets, data):
        # type: (Descriptor, Offsets, bytes) -> None
        """Postpone integrity check for chunk
        :param Descriptor self: this
        :param Offsets offsets: download offsets
        :param bytes data: data
        """
        if len(data) > 0:
            with self.local_path.open('r+b') as fd:
                fd.seek(offsets.fd_start, 0)
                fd.write(data)

    def finalize_file(self):
        # type: (Descriptor) -> None
        """Finalize file download
        :param Descriptor self: this
        """
        with self._meta_lock:
            if self._finalized:
                return
        # check final file integrity
        check = False
        msg = None
        if self.hmac is not None:
            mac = self._ase.encryption_metadata.encryption_authentication.\
                message_authentication_code
            digest = blobxfer.util.base64_encode_as_string(self.hmac.digest())
            if digest == mac:
                check = True
            msg = '{}: {}, {} {} <L..R> {}'.format(
                self._ase.encryption_metadata.encryption_authentication.
                algorithm,
                'OK' if check else 'MISMATCH',
                self._ase.name,
                digest,
                mac,
            )
        elif self.md5 is not None:
            digest = blobxfer.util.base64_encode_as_string(self.md5.digest())
            if digest == self._ase.md5:
                check = True
            msg = 'MD5: {}, {} {} <L..R> {}'.format(
                'OK' if check else 'MISMATCH',
                self._ase.name,
                digest,
                self._ase.md5,
            )
        else:
            check = True
            msg = 'MD5: SKIPPED, {} None <L..R> {}'.format(
                self._ase.name,
                self._ase.md5
            )
        # cleanup if download failed
        if not check:
            logger.error(msg)
            # delete temp download file
            self.local_path.unlink()
            return
        logger.debug(msg)

        # TODO set file uid/gid and mode

        # move temp download file to final path
        blobxfer.util.replace_file(self.local_path, self.final_path)
        # update resume file
        self._update_resume_for_completed()
        with self._meta_lock:
            self._finalized = True
