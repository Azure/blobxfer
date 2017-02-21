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
except ImportError:
    import Queue as queue
# non-stdlib imports
# local imports
import blobxfer.download
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)

# global defines
_TASK_QUEUE = multiprocessing.Queue()
_DONE_QUEUE = multiprocessing.Queue()
_DONE_CV = multiprocessing.Condition()
_MD5_PROCS = []


def _worker_md5_file_process():
    global _TASK_QUEUE, _DONE_QUEUE
    while True:
        filename, remote_md5, pagealign = _TASK_QUEUE.get()
        md5 = blobxfer.util.compute_md5_for_file_asbase64(filename, pagealign)
        logger.debug('MD5: {} <L..R> {} {}'.format(md5, remote_md5, filename))
        _DONE_CV.acquire()
        _DONE_QUEUE.put((filename, md5 == remote_md5))
        _DONE_CV.notify()
        _DONE_CV.release()


def get_done_cv():
    global _DONE_CV
    return _DONE_CV


def check_md5_file_for_download():
    # type: (None) -> str
    """Check queue for a file to download
    :rtype: str
    :return: local file path
    """
    global _DONE_QUEUE
    try:
        return _DONE_QUEUE.get_nowait()
    except queue.Empty:
        return None


def add_file_for_md5_check(filename, remote_md5, mode):
    # type: (str, str, blobxfer.models.AzureStorageModes) -> bool
    """Check an MD5 for a file for download
    :param str filename: file to compute MD5 for
    :param str remote_md5: remote MD5 to compare against
    :param blobxfer.models.AzureStorageModes mode: mode
    :rtype: bool
    :return: MD5 match comparison
    """
    global _TASK_QUEUE
    if mode == blobxfer.models.AzureStorageModes.Page:
        pagealign = True
    else:
        pagealign = False
    _TASK_QUEUE.put((filename, remote_md5, pagealign))


def initialize_md5_processes(num_workers=None):
    global _MD5_PROCS
    if num_workers is None or num_workers < 1:
        num_workers = multiprocessing.cpu_count() // 2
    if num_workers < 1:
        num_workers = 1
    for _ in range(num_workers):
        proc = multiprocessing.Process(target=_worker_md5_file_process)
        proc.start()
        _MD5_PROCS.append(proc)


def finalize_md5_processes():
    global _MD5_PROCS
    for proc in _MD5_PROCS:
        proc.terminate()
        proc.join()
