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
import blobxfer.blob.operations
import blobxfer.file.operations
import blobxfer.crypto.models
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)

# named tuples
DownloadOffsets = collections.namedtuple(
    'DownloadOffsets', [
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


class DownloadDescriptor(object):
    """Download Descriptor"""

    _AES_BLOCKSIZE = blobxfer.crypto.models._AES256_BLOCKSIZE_BYTES

    def __init__(self, lpath, ase, options):
        # type: (DownloadDescriptior, pathlib.Path, AzureStorageEntity,
        #        DownloadOptions) -> None
        """Ctor for DownloadDescriptor
        :param DownloadDescriptor self: this
        :param pathlib.Path lpath: local path
        :param AzureStorageEntity ase: Azure Storage Entity
        :param DownloadOptions options: download options
        """
        self.final_path = lpath
        # create path holding the temporary file to download to
        _tmp = list(lpath.parts[:-1])
        _tmp.append(lpath.name + '.bxtmp')
        self.local_path = pathlib.Path(*_tmp)
        self._meta_lock = threading.Lock()
        self._hasher_lock = threading.Lock()
        self._ase = ase
        # calculate the total number of ops required for transfer
        self._chunk_size = min((options.chunk_size_bytes, self._ase.size))
        try:
            self._total_chunks = int(
                math.ceil(self._ase.size / self._chunk_size))
        except ZeroDivisionError:
            self._total_chunks = 0
        self.hmac = None
        self.md5 = None
        self._offset = 0
        self._chunk_num = 0
        self._next_integrity_chunk = 0
        self._unchecked_chunks = {}
        self._outstanding_ops = self._total_chunks
        self._completed_ops = 0
        # initialize checkers and allocate space
        self._initialize_integrity_checkers(options)
        self._allocate_disk_space()

    @property
    def entity(self):
        # type: (DownloadDescriptor) -> AzureStorageEntity
        """Get linked AzureStorageEntity
        :param DownloadDescriptor self: this
        :rtype: AzureStorageEntity
        :return: AzureStorageEntity
        """
        return self._ase

    @property
    def must_compute_md5(self):
        # type: (DownloadDescriptor) -> bool
        """Check if MD5 must be computed
        :param DownloadDescriptor self: this
        :rtype: bool
        :return: if MD5 must be computed
        """
        return self.md5 is not None

    @property
    def all_operations_completed(self):
        # type: (DownloadDescriptor) -> bool
        """All operations are completed
        :param DownloadDescriptor self: this
        :rtype: bool
        :return: if all operations completed
        """
        with self._meta_lock:
            return (self._outstanding_ops == 0 and
                    len(self._unchecked_chunks) == 0)

    def dec_outstanding_operations(self):
        # type: (DownloadDescriptor) -> None
        """Decrement outstanding operations (and increment completed ops)
        :param DownloadDescriptor self: this
        """
        with self._meta_lock:
            self._outstanding_ops -= 1
            self._completed_ops += 1

    def _initialize_integrity_checkers(self, options):
        # type: (DownloadDescriptor, DownloadOptions) -> None
        """Initialize file integrity checkers
        :param DownloadDescriptor self: this
        :param DownloadOptions options: download options
        """
        if self._ase.is_encrypted:
            # ensure symmetric key exists
            if blobxfer.util.is_none_or_empty(
                    self._ase.encryption_metadata.symmetric_key):
                raise RuntimeError(
                    'symmetric key is invalid: provide RSA private key '
                    'or metadata corrupt')
            self.hmac = self._ase.encryption_metadata.initialize_hmac()
        if self.hmac is None and options.check_file_md5:
            self.md5 = blobxfer.util.new_md5_hasher()

    def _allocate_disk_space(self):
        # type: (DownloadDescriptor, int) -> None
        """Perform file allocation (possibly sparse)
        :param DownloadDescriptor self: this
        :param int size: size
        """
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
        # create parent path
        self.local_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        # allocate file
        with self.local_path.open('wb') as fd:
            if allocatesize > 0:
                try:
                    os.posix_fallocate(fd.fileno(), 0, allocatesize)
                except AttributeError:
                    fd.seek(allocatesize - 1)
                    fd.write(b'\0')

    def next_offsets(self):
        # type: (DownloadDescriptor) -> DownloadOffsets
        """Retrieve the next offsets
        :param DownloadDescriptor self: this
        :rtype: DownloadOffsets
        :return: download offsets
        """
        with self._meta_lock:
            if self._offset >= self._ase.size:
                return None
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
            return DownloadOffsets(
                chunk_num=chunk_num,
                fd_start=fd_start,
                num_bytes=chunk,
                range_start=range_start,
                range_end=range_end,
                unpad=unpad,
            )

    def _postpone_integrity_check(self, offsets, data):
        # type: (DownloadDescriptor, DownloadOffsets, bytes) -> None
        """Postpone integrity check for chunk
        :param DownloadDescriptor self: this
        :param DownloadOffsets offsets: download offsets
        :param bytes data: data
        """
        if self.must_compute_md5:
            with self.local_path.open('r+b') as fd:
                fd.seek(offsets.fd_start, 0)
                fd.write(data)
            unchecked = UncheckedChunk(
                data_len=len(data),
                fd_start=offsets.fd_start,
                file_path=self.local_path,
                temp=False,
            )
        else:
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

    def perform_chunked_integrity_check(self, offsets, data):
        # type: (DownloadDescriptor, DownloadOffsets, bytes) -> None
        """Hash data against stored MD5 hasher safely
        :param DownloadDescriptor self: this
        :param DownloadOffsets offsets: download offsets
        :param bytes data: data
        """
        self_check = False
        hasher = self.hmac or self.md5
        # iterate from next chunk to be checked
        while True:
            ucc = None
            with self._meta_lock:
                chunk_num = self._next_integrity_chunk
                # check if the next chunk is ready
                if chunk_num in self._unchecked_chunks:
                    ucc = self._unchecked_chunks.pop(chunk_num)
                elif chunk_num != offsets.chunk_num:
                    break
            # prepare data for hashing
            if ucc is None:
                chunk = data
                self_check = True
            else:
                with ucc.file_path.open('rb') as fd:
                    fd.seek(ucc.fd_start, 0)
                    chunk = fd.read(ucc.data_len)
                if ucc.temp:
                    ucc.file_path.unlink()
            # hash data and set next integrity chunk
            with self._hasher_lock:
                hasher.update(chunk)
            with self._meta_lock:
                self._next_integrity_chunk += 1
        # store data that hasn't been checked
        if not self_check:
            self._postpone_integrity_check(offsets, data)

    def write_data(self, offsets, data):
        # type: (DownloadDescriptor, DownloadOffsets, bytes) -> None
        """Postpone integrity check for chunk
        :param DownloadDescriptor self: this
        :param DownloadOffsets offsets: download offsets
        :param bytes data: data
        """
        with self.local_path.open('r+b') as fd:
            fd.seek(offsets.fd_start, 0)
            fd.write(data)

    def finalize_file(self):
        # type: (DownloadDescriptor) -> None
        """Finalize file download
        :param DownloadDescriptor self: this
        """
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
        self.local_path.rename(self.final_path)
