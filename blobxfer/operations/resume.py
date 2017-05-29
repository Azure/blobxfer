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
import contextlib
import logging
import pickle
import shelve
import threading
# non-stdlib imports
# local imports
import blobxfer.models.resume
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


class DownloadResumeManager():
    """Download Resume Manager"""
    def __init__(self, resume_file):
        # type: (DownloadResumeManager, str) -> None
        """Ctor for DownloadResumeManager
        :param DownloadResumeManager self: this
        :param pathlib.Path resume_file: resume file
        """
        self._lock = threading.Lock()
        self._resume_file = resume_file
        self._data = shelve.open(
            str(resume_file), protocol=pickle.HIGHEST_PROTOCOL)

    def close(self):
        # type: (DownloadResumeManager) -> None
        """Close the internal data store
        :param DownloadResumeManager self: this
        """
        if self._data is not None:
            self._data.close()
            self._data = None

    def delete(self):
        # type: (DownloadResumeManager) -> None
        """Delete the resume file db
        :param DownloadResumeManager self: this
        """
        self.close()
        try:
            self._resume_file.unlink()
        except OSError as e:
            logger.warning('could not unlink resume db: {}'.format(e))

    @contextlib.contextmanager
    def datalock(self, acquire=True):
        # type: (DownloadResumeManager) -> None
        """Delete the resume file db
        :param DownloadResumeManager self: this
        :param bool acquire: acquire lock
        """
        if acquire:
            self._lock.acquire()
        try:
            yield
        finally:
            if acquire:
                self._lock.release()

    @staticmethod
    def generate_record_key(ase):
        # type: (blobxfer.models.azure.StorageEntity) -> str
        """Generate a record key
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :rtype: str
        :return: record key
        """
        return '{}:{}'.format(ase._client.primary_endpoint, ase.path)

    def get_record(self, ase, key=None, lock=True):
        # type: (DownloadResumeManager, str,
        #        bool) -> blobxfer.models.resume.Download
        """Get a resume record
        :param DownloadResumeManager self: this
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :param str key: record key
        :param bool lock: acquire lock
        :rtype: blobxfer.models.resume.Download
        :return: Download record
        """
        if key is None:
            key = blobxfer.operations.resume.DownloadResumeManager.\
                generate_record_key(ase)
        with self.datalock(lock):
            try:
                return self._data[key]
            except KeyError:
                return None

    def add_or_update_record(
            self, final_path, ase, chunk_size, next_integrity_chunk,
            completed, md5):
        # type: (DownloadResumeManager, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity, int, int, bool,
        #        str) -> None
        """Get a resume record
        :param DownloadResumeManager self: this
        :param pathlib.Path final_path: final path
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :param int chunk_size: chunk size in bytes
        :param int next_integrity_chunk: next integrity chunk
        :param bool completed: if completed
        :param str md5: md5 hex digest
        """
        key = blobxfer.operations.resume.DownloadResumeManager.\
            generate_record_key(ase)
        with self.datalock():
            dl = self.get_record(ase, key=key, lock=False)
            if dl is None:
                dl = blobxfer.models.resume.Download(
                    final_path=str(final_path),
                    length=ase._size,
                    chunk_size=chunk_size,
                    next_integrity_chunk=next_integrity_chunk,
                    completed=completed,
                    md5=md5,
                )
            else:
                if (dl.completed or
                        next_integrity_chunk < dl.next_integrity_chunk):
                    return
                if completed:
                    dl.completed = completed
                else:
                    dl.next_integrity_chunk = next_integrity_chunk
                    dl.md5hexdigest = md5
            self._data[key] = dl
            self._data.sync()
