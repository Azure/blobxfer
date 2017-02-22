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
import multiprocessing
try:
    import queue
except ImportError:  # noqa
    import Queue as queue
# non-stdlib imports
# local imports
import blobxfer.download
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


class LocalFileMd5Offload(object):
    """LocalFileMd5Offload"""
    def __init__(self, num_workers=None):
        # type: (LocalFileMd5Offload, int) -> None
        """Ctor for Local File Md5 Offload
        :param LocalFileMd5Offload self: this
        :param int num_workers: number of worker processes
        """
        self._task_queue = multiprocessing.Queue()
        self._done_queue = multiprocessing.Queue()
        self._done_cv = multiprocessing.Condition()
        self._term_signal = multiprocessing.Value('i', 0)
        self._md5_procs = []
        self._initialize_md5_processes(num_workers)

    @property
    def done_cv(self):
        # type: (LocalFileMd5Offload) -> multiprocessing.Condition
        """Get Download Done condition variable
        :param LocalFileMd5Offload self: this
        :rtype: multiprocessing.Condition
        :return: cv for download done
        """
        return self._done_cv

    def _initialize_md5_processes(self, num_workers=None):
        # type: (LocalFileMd5Offload, int) -> None
        """Initialize MD5 checking processes for files for download
        :param LocalFileMd5Offload self: this
        :param int num_workers: number of worker processes
        """
        if num_workers is None:
            num_workers = multiprocessing.cpu_count() // 2
        if num_workers < 1:
            num_workers = 1
        for _ in range(num_workers):
            proc = multiprocessing.Process(
                target=self._worker_compute_md5_localfile_process)
            proc.start()
            self._md5_procs.append(proc)

    def finalize_md5_processes(self):
        # type: (LocalFileMd5Offload) -> None
        """Finalize MD5 checking processes for files for download
        :param LocalFileMd5Offload self: this
        """
        self._term_signal.value = 1
        for proc in self._md5_procs:
            proc.join()

    def _worker_compute_md5_localfile_process(self):
        # type: (LocalFileMd5Offload) -> None
        """Compute MD5 for local file
        :param LocalFileMd5Offload self: this
        """
        while self._term_signal.value == 0:
            try:
                filename, remote_md5, pagealign = self._task_queue.get(True, 1)
            except queue.Empty:
                continue
            md5 = blobxfer.util.compute_md5_for_file_asbase64(
                filename, pagealign)
            logger.debug('MD5: {} <L..R> {} {}'.format(
                md5, remote_md5, filename))
            self._done_cv.acquire()
            self._done_queue.put((filename, md5 == remote_md5))
            self.done_cv.notify()
            self.done_cv.release()

    def get_localfile_md5_done(self):
        # type: (LocalFileMd5Offload) -> Tuple[str, bool]
        """Get from done queue of local files with MD5 completed
        :param LocalFileMd5Offload self: this
        :rtype: tuple or None
        :return: (local file path, md5 match)
        """
        try:
            return self._done_queue.get_nowait()
        except queue.Empty:
            return None

    def add_localfile_for_md5_check(self, filename, remote_md5, mode):
        # type: (LocalFileMd5Offload, str, str,
        #        blobxfer.models.AzureStorageModes) -> bool
        """Check an MD5 for a file for download
        :param LocalFileMd5Offload self: this
        :param str filename: file to compute MD5 for
        :param str remote_md5: remote MD5 to compare against
        :param blobxfer.models.AzureStorageModes mode: mode
        :rtype: bool
        :return: MD5 match comparison
        """
        if mode == blobxfer.models.AzureStorageModes.Page:
            pagealign = True
        else:
            pagealign = False
        self._task_queue.put((filename, remote_md5, pagealign))
