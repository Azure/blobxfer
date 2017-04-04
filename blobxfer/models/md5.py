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
import blobxfer.operations.md5

# create logger
logger = logging.getLogger(__name__)


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
                filename, remote_md5, pagealign = self._task_queue.get(True, 1)
            except queue.Empty:
                continue
            md5 = blobxfer.operations.md5.compute_md5_for_file_asbase64(
                filename, pagealign)
            logger.debug('MD5: {} <L..R> {} {}'.format(
                md5, remote_md5, filename))
            self._done_cv.acquire()
            self._done_queue.put((filename, md5 == remote_md5))
            self._done_cv.notify()
            self._done_cv.release()

    def add_localfile_for_md5_check(self, filename, remote_md5, mode):
        # type: (LocalFileMd5Offload, str, str,
        #        blobxfer.models.azure.StorageModes) -> None
        """Add a local file to MD5 check queue
        :param LocalFileMd5Offload self: this
        :param str filename: file to compute MD5 for
        :param str remote_md5: remote MD5 to compare against
        :param blobxfer.models.azure.StorageModes mode: mode
        """
        if mode == blobxfer.models.azure.StorageModes.Page:
            pagealign = True
        else:
            pagealign = False
        self._task_queue.put((filename, remote_md5, pagealign))
