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
            self, final_path, temp_path, length, chunk_size,
            next_integrity_chunk, completed, md5):
        # type: (Download, str, str, int, int, int, str) -> None
        """Ctor for Download
        :param Download self: this
        :param str final_path: final path
        :param str temp_path: temporary path
        :param int length: total bytes
        :param int chunk_size: chunk size in bytes
        :param int next_integrity_chunk: next integrity chunk
        :param str md5: md5 hex digest
        """
        self._final_path = final_path
        self._temp_path = temp_path
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
    def temp_path(self):
        # type: (Download) -> str
        """Temp path
        :param Download self: this
        :rtype: str
        :return: temp path
        """
        return self._temp_path

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
        return ('Download<final_path={} temp_path={} length={} chunk_size={} '
                'next_integrity_chunk={} completed={} md5={}>').format(
                    self.final_path, self.temp_path, self.length,
                    self.chunk_size, self.next_integrity_chunk,
                    self.completed, self.md5hexdigest,
                )
