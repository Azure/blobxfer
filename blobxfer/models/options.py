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
import multiprocessing
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# local imports
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_DEFAULT_REQUESTS_TIMEOUT = (3.1, 12.1)

# named tuples
HttpProxy = collections.namedtuple(
    'HttpProxy', [
        'host',
        'port',
        'username',
        'password',
    ]
)
VectoredIo = collections.namedtuple(
    'VectoredIoOptions', [
        'stripe_chunk_size_bytes',
        'distribution_mode',
    ]
)
SkipOn = collections.namedtuple(
    'SkipOn', [
        'filesize_match',
        'lmt_ge',
        'md5_match',
    ]
)
FileProperties = collections.namedtuple(
    'FileProperties', [
        'attributes',
        'md5',
    ]
)
Upload = collections.namedtuple(
    'Upload', [
        'access_tier',
        'chunk_size_bytes',
        'delete_extraneous_destination',
        'mode',
        'one_shot_bytes',
        'overwrite',
        'recursive',
        'rename',
        'rsa_public_key',
        'stdin_as_page_blob_size',
        'store_file_properties',
        'strip_components',
        'vectored_io',
    ]
)
Download = collections.namedtuple(
    'Download', [
        'check_file_md5',
        'chunk_size_bytes',
        'delete_extraneous_destination',
        'mode',
        'overwrite',
        'recursive',
        'rename',
        'restore_file_attributes',
        'rsa_private_key',
        'strip_components',
    ]
)
SyncCopy = collections.namedtuple(
    'SyncCopy', [
        'access_tier',
        'delete_extraneous_destination',
        'dest_mode',
        'mode',
        'overwrite',
        'recursive',
        'rename',
    ]
)


class Timeout(object):
    """Timeout Options"""
    def __init__(self, connect, read, max_retries):
        """Ctor for Timeout options
        :param Timeout self: this
        :param float connect: connect timeout
        :param float read: read timeout
        :param int max_retries: max retries
        """
        if connect is None or connect <= 0:
            self._connect = _DEFAULT_REQUESTS_TIMEOUT[0]
        else:
            self._connect = connect
        if read is None or read <= 0:
            self._read = _DEFAULT_REQUESTS_TIMEOUT[1]
        else:
            self._read = read
        if max_retries is None or max_retries < 0:
            self._max_retries = None
        else:
            self._max_retries = max_retries

    @property
    def connect(self):
        """Connect timeout
        :rtype: float
        :return: connect timeout
        """
        return self._connect

    @property
    def read(self):
        """Read timeout
        :rtype: float
        :return: read timeout
        """
        return self._read

    @property
    def timeout(self):
        """Timeout property in requests format
        :rtype: tuple
        :return: (connect, read) timeout tuple
        """
        return (self._connect, self._read)

    @property
    def max_retries(self):
        """Max retries
        :rtype: int
        :return maximum number of retries
        """
        return self._max_retries


class Concurrency(object):
    """Concurrency Options"""
    def __init__(
            self, crypto_processes, md5_processes, disk_threads,
            transfer_threads, action=None):
        """Ctor for Concurrency Options
        :param Concurrency self: this
        :param int crypto_processes: number of crypto procs
        :param int md5_processes: number of md5 procs
        :param int disk_threads: number of disk threads
        :param int transfer_threads: number of transfer threads
        :param int action: action hint (1=Download, 2=Upload, 3=SyncCopy)
        """
        self.crypto_processes = crypto_processes
        self.md5_processes = md5_processes
        self.disk_threads = disk_threads
        self.transfer_threads = transfer_threads
        # allow crypto processes to be zero (which will inline crypto
        # routines with main process)
        if self.crypto_processes is None or self.crypto_processes < 1:
            self.crypto_processes = 0
        if self.md5_processes is None or self.md5_processes < 1:
            self.md5_processes = multiprocessing.cpu_count() >> 1
        if self.md5_processes < 1:
            self.md5_processes = 1
        auto_disk = False
        if self.disk_threads is None or self.disk_threads < 1:
            self.disk_threads = multiprocessing.cpu_count() << 1
            # cap maximum number of disk threads from cpu count to 64
            if self.disk_threads > 64:
                self.disk_threads = 64
            # for download action, cap disk threads to lower value
            if action == 1 and self.disk_threads > 32:
                self.disk_threads = 32
            auto_disk = True
        # for synccopy action, set all non-transfer counts to zero
        if action == 3:
            auto_disk = False
            self.md5_processes = 0
            self.crypto_processes = 0
            self.disk_threads = 0
        if self.transfer_threads is None or self.transfer_threads < 1:
            if auto_disk:
                # for download action, cap network threads to lower value
                if action == 1:
                    max_threads = (multiprocessing.cpu_count() >> 1) - 2
                    if max_threads < 3:
                        max_threads = 3
                    self.transfer_threads = max_threads
                    self.disk_threads = int(max_threads * 1.5)
                else:
                    self.transfer_threads = self.disk_threads << 1
            else:
                self.transfer_threads = multiprocessing.cpu_count() << 2
            # cap maximum number of threads from cpu count to 96
            if self.transfer_threads > 96:
                self.transfer_threads = 96


class General(object):
    """General Options"""
    def __init__(
            self, concurrency, log_file=None, progress_bar=True,
            resume_file=None, timeout=None, verbose=False, quiet=False,
            proxy=None):
        """Ctor for General Options
        :param General self: this
        :param Concurrency concurrency: concurrency options
        :param bool progress_bar: progress bar
        :param str log_file: log file
        :param str resume_file: resume file
        :param Timeout timeout: timeout options
        :param bool verbose: verbose output
        :param bool quiet: quiet
        :param HttpProxy proxy: proxy
        """
        if concurrency is None:
            raise ValueError('concurrency option is unspecified')
        self.concurrency = concurrency
        self.log_file = log_file
        self.progress_bar = progress_bar
        if blobxfer.util.is_not_empty(resume_file):
            self.resume_file = pathlib.Path(resume_file)
        else:
            self.resume_file = None
        self.timeout = timeout
        self.verbose = verbose
        self.quiet = quiet
        self.proxy = proxy
