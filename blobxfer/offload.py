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
import logging
import multiprocessing
import threading
try:
    import queue
except ImportError:  # noqa
    import Queue as queue

# create logger
logger = logging.getLogger(__name__)


class _MultiprocessOffload(object):
    def __init__(self, target, num_workers, description=None):
        # type: (_MultiprocessOffload, function, int, str) -> None
        """Ctor for Crypto Offload
        :param _MultiprocessOffload self: this
        :param function target: target function for process
        :param int num_workers: number of worker processes
        :param str description: description
        """
        self._task_queue = multiprocessing.Queue()
        self._done_queue = multiprocessing.Queue()
        self._done_cv = multiprocessing.Condition()
        self._term_signal = multiprocessing.Value('i', 0)
        self._procs = []
        self._check_thread = None
        self._initialize_processes(target, num_workers, description)

    @property
    def done_cv(self):
        # type: (_MultiprocessOffload) -> multiprocessing.Condition
        """Get Done condition variable
        :param _MultiprocessOffload self: this
        :rtype: multiprocessing.Condition
        :return: cv for download done
        """
        return self._done_cv

    @property
    def terminated(self):
        # type: (_MultiprocessOffload) -> bool
        """Check if terminated
        :param _MultiprocessOffload self: this
        :rtype: bool
        :return: if terminated
        """
        return self._term_signal.value == 1

    def _initialize_processes(self, target, num_workers, description):
        # type: (_MultiprocessOffload, function, int, str) -> None
        """Initialize processes
        :param _MultiprocessOffload self: this
        :param function target: target function for process
        :param int num_workers: number of worker processes
        :param str description: description
        """
        if num_workers is None or num_workers < 1:
            raise ValueError('invalid num_workers: {}'.format(num_workers))
        logger.debug('initializing {}{} processes'.format(
            num_workers, ' ' + description if not None else ''))
        for _ in range(num_workers):
            proc = multiprocessing.Process(target=target)
            proc.start()
            self._procs.append(proc)

    def finalize_processes(self):
        # type: (_MultiprocessOffload) -> None
        """Finalize processes
        :param _MultiprocessOffload self: this
        """
        self._term_signal.value = 1
        if self._check_thread is not None:
            self._check_thread.join()
        for proc in self._procs:
            proc.join()

    def pop_done_queue(self):
        # type: (_MultiprocessOffload) -> object
        """Get item from done queue
        :param _MultiprocessOffload self: this
        :rtype: object or None
        :return: object from done queue, if exists
        """
        try:
            return self._done_queue.get_nowait()
        except queue.Empty:
            return None

    def initialize_check_thread(self, check_func):
        # type: (_MultiprocessOffload, function) -> None
        """Initialize the crypto done queue check thread
        :param Downloader self: this
        :param function check_func: check function
        """
        self._check_thread = threading.Thread(target=check_func)
        self._check_thread.start()
