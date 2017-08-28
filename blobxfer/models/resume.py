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
# non-stdlib imports
# local imports


class Download(object):
    """Download resume object"""
    def __init__(
            self, final_path, length, chunk_size, next_integrity_chunk,
            completed, md5):
        # type: (Download, str, int, int, int, bool, str) -> None
        """Ctor for Download
        :param Download self: this
        :param str final_path: final path
        :param int length: total bytes
        :param int chunk_size: chunk size in bytes
        :param int next_integrity_chunk: next integrity chunk
        :param bool completed: completed
        :param str md5: md5 hex digest
        """
        self._final_path = final_path
        self._length = length
        self._chunk_size = chunk_size
        self._next_integrity_chunk = next_integrity_chunk
        self._completed = completed
        self._md5hexdigest = md5 if md5 is not None else None

    @property
    def final_path(self):
        # type: (Download) -> str
        """Final path
        :param Download self: this
        :rtype: str
        :return: final path
        """
        return self._final_path

    @property
    def length(self):
        # type: (Download) -> int
        """Content length
        :param Download self: this
        :rtype: int
        :return: number of bytes
        """
        return self._length

    @property
    def chunk_size(self):
        # type: (Download) -> int
        """Chunk size
        :param Download self: this
        :rtype: int
        :return: chunk size in bytes
        """
        return self._chunk_size

    @property
    def next_integrity_chunk(self):
        # type: (Download) -> int
        """Get Next integrity chunk
        :param Download self: this
        :rtype: int
        :return: next integrity chunk
        """
        return self._next_integrity_chunk

    @next_integrity_chunk.setter
    def next_integrity_chunk(self, value):
        # type: (Download) -> None
        """Set Next integrity chunk
        :param Download self: this
        :param int value: next chunk num
        """
        self._next_integrity_chunk = value

    @property
    def completed(self):
        # type: (Download) -> bool
        """Get Completed
        :param Download self: this
        :rtype: bool
        :return: if completed
        """
        return self._completed

    @completed.setter
    def completed(self, value):
        # type: (Download) -> None
        """Set Completed
        :param Download self: this
        :param bool value: completion value
        """
        self._completed = value

    @property
    def md5hexdigest(self):
        # type: (Download) -> str
        """Get md5 hex digest
        :param Download self: this
        :rtype: str
        :return: md5 hex digest
        """
        return self._md5hexdigest

    @md5hexdigest.setter
    def md5hexdigest(self, value):
        # type: (Download) -> None
        """Set md5 hex digest value if value is not None
        :param Download self: this
        :param str value: md5 hex digest
        """
        if value is None:
            return
        self._md5hexdigest = value

    def __repr__(self):
        # type: (Download) -> str
        """Return representation
        :param Download self: this
        :rtype: str
        :return: representation string
        """
        return ('Download<final_path={} length={} chunk_size={} '
                'next_integrity_chunk={} completed={} md5={}>').format(
                    self.final_path, self.length, self.chunk_size,
                    self.next_integrity_chunk, self.completed,
                    self.md5hexdigest)


class Upload(object):
    """Upload resume object"""
    def __init__(
            self, local_path, length, chunk_size, total_chunks,
            completed_chunks, completed, md5):
        # type: (Upload, str, int, int, int, int, bool, str) -> None
        """Ctor for Upload
        :param Upload self: this
        :param str local_path: local path
        :param int length: total bytes
        :param int chunk_size: chunk size in bytes
        :param int total_chunks: total chunks
        :param int completed_chunks: completed chunks
        :param bool completed: completed
        :param str md5: md5 hex digest
        """
        self._local_path = local_path
        self._length = length
        self._chunk_size = chunk_size
        self._total_chunks = total_chunks
        self._completed_chunks = completed_chunks
        self._completed = completed
        self._md5hexdigest = md5 if md5 is not None else None

    @property
    def local_path(self):
        # type: (Upload) -> str
        """Local path
        :param Upload self: this
        :rtype: str
        :return: local path
        """
        return self._local_path

    @property
    def length(self):
        # type: (Upload) -> int
        """Content length
        :param Upload self: this
        :rtype: int
        :return: number of bytes
        """
        return self._length

    @property
    def chunk_size(self):
        # type: (Upload) -> int
        """Chunk size
        :param Upload self: this
        :rtype: int
        :return: chunk size in bytes
        """
        return self._chunk_size

    @property
    def total_chunks(self):
        # type: (Upload) -> int
        """Get total number of chunks
        :param Upload self: this
        :rtype: int
        :return: total chunks
        """
        return self._total_chunks

    @property
    def completed_chunks(self):
        # type: (Upload) -> int
        """Get Completed chunks
        :param Upload self: this
        :rtype: int
        :return: completed chunks
        """
        return self._completed_chunks

    @completed_chunks.setter
    def completed_chunks(self, value):
        # type: (Upload, int) -> None
        """Set Completed chunks
        :param Upload self: this
        :param int value: completed chunks
        """
        self._completed_chunks = value

    @property
    def completed(self):
        # type: (Upload) -> bool
        """Get Completed
        :param Upload self: this
        :rtype: bool
        :return: if completed
        """
        return self._completed

    @completed.setter
    def completed(self, value):
        # type: (Upload) -> None
        """Set Completed
        :param Upload self: this
        :param bool value: completion value
        """
        self._completed = value

    @property
    def md5hexdigest(self):
        # type: (Upload) -> str
        """Get md5 hex digest
        :param Upload self: this
        :rtype: str
        :return: md5 hex digest
        """
        return self._md5hexdigest

    @md5hexdigest.setter
    def md5hexdigest(self, value):
        # type: (Upload) -> None
        """Set md5 hex digest value if value is not None
        :param Upload self: this
        :param str value: md5 hex digest
        """
        if value is None:
            return
        self._md5hexdigest = value

    def __repr__(self):
        # type: (Upload) -> str
        """Return representation
        :param Upload self: this
        :rtype: str
        :return: representation string
        """
        return ('Upload<local_path={} length={} chunk_size={} '
                'total_chunks={} completed_chunks={} completed={} '
                'md5={}>').format(
                    self.local_path, self.length, self.chunk_size,
                    self.total_chunks, self.completed_chunks, self.completed,
                    self.md5hexdigest)


class SyncCopy(object):
    """SyncCopy resume object"""
    def __init__(
            self, length, src_block_list, offset, chunk_size, total_chunks,
            completed_chunks, completed):
        # type: (SyncCopy, int, int, int, int, bool) -> None
        """Ctor for SyncCopy
        :param SyncCopy self: this
        :param int length: total bytes
        :param int chunk_size: chunk size in bytes
        :param int total_chunks: total chunks
        :param int completed_chunks: completed chunks
        :param bool completed: completed
        """
        self._length = length
        self._src_block_list = src_block_list
        self._offset = offset
        self._chunk_size = chunk_size
        self._total_chunks = total_chunks
        self._completed_chunks = completed_chunks
        self._completed = completed

    @property
    def length(self):
        # type: (SyncCopy) -> int
        """Content length
        :param SyncCopy self: this
        :rtype: int
        :return: number of bytes
        """
        return self._length

    @property
    def src_block_list(self):
        # type: (SyncCopy) -> list
        """Source committed block list
        :param SyncCopy self: this
        :rtype: list
        :return: source committed block list
        """
        return self._src_block_list

    @property
    def offset(self):
        # type: (SyncCopy) -> int
        """Current offset
        :param SyncCopy self: this
        :rtype: int
        :return: current offset
        """
        return self._offset

    @offset.setter
    def offset(self, value):
        # type: (SyncCopy, int) -> None
        """Set offset
        :param SyncCopy self: this
        :param int value: offset
        """
        self._offset = value

    @property
    def chunk_size(self):
        # type: (SyncCopy) -> int
        """Chunk size
        :param SyncCopy self: this
        :rtype: int
        :return: chunk size in bytes
        """
        return self._chunk_size

    @property
    def total_chunks(self):
        # type: (SyncCopy) -> int
        """Get total number of chunks
        :param SyncCopy self: this
        :rtype: int
        :return: total chunks
        """
        return self._total_chunks

    @property
    def completed_chunks(self):
        # type: (SyncCopy) -> int
        """Get Completed chunks
        :param SyncCopy self: this
        :rtype: int
        :return: completed chunks
        """
        return self._completed_chunks

    @completed_chunks.setter
    def completed_chunks(self, value):
        # type: (SyncCopy, int) -> None
        """Set Completed chunks
        :param SyncCopy self: this
        :param int value: completed chunks
        """
        self._completed_chunks = value

    @property
    def completed(self):
        # type: (SyncCopy) -> bool
        """Get Completed
        :param SyncCopy self: this
        :rtype: bool
        :return: if completed
        """
        return self._completed

    @completed.setter
    def completed(self, value):
        # type: (SyncCopy) -> None
        """Set Completed
        :param SyncCopy self: this
        :param bool value: completion value
        """
        self._completed = value

    def __repr__(self):
        # type: (SyncCopy) -> str
        """Return representation
        :param SyncCopy self: this
        :rtype: str
        :return: representation string
        """
        return ('SyncCopy<length={} chunk_size={} total_chunks={} '
                'completed_chunks={} completed={}>').format(
                    self.length, self.chunk_size, self.total_chunks,
                    self.completed_chunks, self.completed)
