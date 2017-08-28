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
try:
    import queue
except ImportError:  # noqa
    import Queue as queue
# non-stdlib imports
# local imports
import blobxfer.models.azure
import blobxfer.models.offload
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_EMPTY_MAX_PAGE_SIZE_MD5 = 'tc+p1sj+vWGPkawoQ9UKHA=='
_MAX_PAGE_SIZE_BYTES = 4194304


def compute_md5_for_file_asbase64(
        filename, pagealign=False, start=None, end=None, blocksize=65536):
    # type: (str, bool, int, int, int) -> str
    """Compute MD5 hash for file and encode as Base64
    :param str filename: file to compute MD5 for
    :param bool pagealign: page align data
    :param int start: file start offset
    :param int end: file end offset
    :param int blocksize: block size
    :rtype: str
    :return: MD5 for file encoded as Base64
    """
    hasher = blobxfer.util.new_md5_hasher()
    with open(filename, 'rb') as filedesc:
        if start is not None:
            filedesc.seek(start)
            curr = start
        else:
            curr = 0
        while True:
            if end is not None and curr + blocksize > end:
                blocksize = end - curr
            if blocksize == 0:
                break
            buf = filedesc.read(blocksize)
            if not buf:
                break
            buflen = len(buf)
            if pagealign and buflen < blocksize:
                aligned = blobxfer.util.page_align_content_length(buflen)
                if aligned != buflen:
                    buf = buf.ljust(aligned, b'\0')
            hasher.update(buf)
            curr += blocksize
        return blobxfer.util.base64_encode_as_string(hasher.digest())


def compute_md5_for_data_asbase64(data):
    # type: (obj) -> str
    """Compute MD5 hash for bits and encode as Base64
    :param any data: data to compute MD5 for
    :rtype: str
    :return: MD5 for data
    """
    hasher = blobxfer.util.new_md5_hasher()
    hasher.update(data)
    return blobxfer.util.base64_encode_as_string(hasher.digest())


def check_data_is_empty(data):
    # type: (bytes) -> bool
    """Check if data is empty via MD5
    :param bytes data: data to check
    :rtype: bool
    :return: if data is empty
    """
    contentmd5 = compute_md5_for_data_asbase64(data)
    datalen = len(data)
    if datalen == _MAX_PAGE_SIZE_BYTES:
        if contentmd5 == _EMPTY_MAX_PAGE_SIZE_MD5:
            return True
    else:
        data_chk = b'\0' * datalen
        if compute_md5_for_data_asbase64(data_chk) == contentmd5:
            return True
    return False


class LocalFileMd5Offload(blobxfer.models.offload._MultiprocessOffload):
    """LocalFileMd5Offload"""
    def __init__(self, num_workers):
        # type: (LocalFileMd5Offload, int) -> None
        """Ctor for Local File Md5 Offload
        :param LocalFileMd5Offload self: this
        :param int num_workers: number of worker processes
        """
        super(LocalFileMd5Offload, self).__init__(
            self._worker_process, num_workers, 'MD5')

    def _worker_process(self):
        # type: (LocalFileMd5Offload) -> None
        """Compute MD5 for local file
        :param LocalFileMd5Offload self: this
        """
        while not self.terminated:
            try:
                key, lpath, fpath, remote_md5, pagealign, lpview = \
                    self._task_queue.get(True, 0.1)
            except queue.Empty:
                continue
            if lpview is None:
                start = None
                end = None
                size = None
            else:
                start = lpview.fd_start
                end = lpview.fd_end
                size = end - start
            md5 = blobxfer.operations.md5.compute_md5_for_file_asbase64(
                fpath, pagealign, start, end)
            logger.debug('pre-transfer MD5 check: {} <L..R> {} {}'.format(
                md5, remote_md5, fpath))
            self._done_cv.acquire()
            self._done_queue.put((key, lpath, size, md5 == remote_md5))
            self._done_cv.notify()
            self._done_cv.release()

    def add_localfile_for_md5_check(
            self, key, lpath, fpath, remote_md5, mode, lpview):
        # type: (LocalFileMd5Offload, str, str, str, str,
        #        blobxfer.models.azure.StorageModes, object) -> None
        """Add a local file to MD5 check queue
        :param LocalFileMd5Offload self: this
        :param str key: md5 map key
        :param str lpath: "local" path for descriptor
        :param str fpath: "final" path for/where file
        :param str remote_md5: remote MD5 to compare against
        :param blobxfer.models.azure.StorageModes mode: mode
        :param object lpview: local path view
        """
        if blobxfer.util.is_none_or_empty(remote_md5):
            raise ValueError('comparison MD5 is empty for file {}'.format(
                lpath))
        if mode == blobxfer.models.azure.StorageModes.Page:
            pagealign = True
        else:
            pagealign = False
        self._task_queue.put(
            (key, lpath, fpath, remote_md5, pagealign, lpview)
        )
