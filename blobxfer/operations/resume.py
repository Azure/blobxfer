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
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
import pickle
import shelve
import threading
# non-stdlib imports
# local imports
import blobxfer.models.resume
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


class _BaseResumeManager(object):
    """Base Resume Manager"""
    def __init__(self, resume_file):
        # type: (_BaseResumeManager, str) -> None
        """Ctor for _BaseResumeManager
        :param _BaseResumeManager self: this
        :param pathlib.Path resume_file: resume file
        """
        self._lock = threading.Lock()
        self._resume_file = resume_file
        self._data = shelve.open(
            str(resume_file), protocol=pickle.HIGHEST_PROTOCOL)

    def close(self):
        # type: (_BaseResumeManager) -> None
        """Close the internal data store
        :param _BaseResumeManager self: this
        """
        if self._data is not None:
            self._data.close()
            self._data = None

    def delete(self):
        # type: (_BaseResumeManager) -> None
        """Delete the resume file db
        :param _BaseResumeManager self: this
        """
        self.close()
        try:
            if not blobxfer.util.on_python2() and blobxfer.util.on_windows():
                for ext in ('.bak', '.dat', '.dir'):
                    fp = pathlib.Path(str(self._resume_file) + ext)
                    fp.unlink()
            else:
                self._resume_file.unlink()
        except OSError as e:
            logger.warning('could not unlink resume db: {}'.format(e))

    @contextlib.contextmanager
    def datalock(self, acquire=True):
        # type: (_BaseResumeManager) -> None
        """Delete the resume file db
        :param _BaseResumeManager self: this
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
        key = '{}:{}'.format(ase._client.primary_endpoint, ase.path)
        if blobxfer.util.on_python2():
            return key.encode('utf8')
        else:
            return key

    def get_record(self, ase, key=None, lock=True):
        # type: (_BaseResumeManager, str, bool) -> object
        """Get a resume record
        :param _BaseResumeManager self: this
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :param str key: record key
        :param bool lock: acquire lock
        :rtype: object
        :return: resume record object
        """
        if key is None:
            key = blobxfer.operations.resume._BaseResumeManager.\
                generate_record_key(ase)
        with self.datalock(lock):
            try:
                return self._data[key]
            except KeyError:
                return None


class DownloadResumeManager(_BaseResumeManager):
    """Download Resume Manager"""
    def __init__(self, resume_file):
        # type: (DownloadResumeManager, str) -> None
        """Ctor for DownloadResumeManager
        :param DownloadResumeManager self: this
        :param pathlib.Path resume_file: resume file
        """
        super(DownloadResumeManager, self).__init__(resume_file)

    def add_or_update_record(
            self, final_path, ase, chunk_size, next_integrity_chunk,
            completed, md5):
        # type: (DownloadResumeManager, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity, int, int, bool,
        #        str) -> None
        """Add or update a resume record
        :param DownloadResumeManager self: this
        :param pathlib.Path final_path: final path
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :param int chunk_size: chunk size in bytes
        :param int next_integrity_chunk: next integrity chunk
        :param bool completed: if completed
        :param str md5: md5 hex digest
        """
        key = blobxfer.operations.resume._BaseResumeManager.\
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


class UploadResumeManager(_BaseResumeManager):
    """Upload Resume Manager"""
    def __init__(self, resume_file):
        # type: (UploadResumeManager, str) -> None
        """Ctor for UploadResumeManager
        :param UploadResumeManager self: this
        :param pathlib.Path resume_file: resume file
        """
        super(UploadResumeManager, self).__init__(resume_file)

    def add_or_update_record(
            self, local_path, ase, chunk_size, total_chunks, completed_chunks,
            completed, md5):
        # type: (UploadResumeManager, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity, int, int, int, bool,
        #        str) -> None
        """Add or update a resume record
        :param UploadResumeManager self: this
        :param pathlib.Path local_path: local path
        :param blobxfer.models.azure.StorageEntity ase: Storage Entity
        :param int chunk_size: chunk size in bytes
        :param int total_chunks: total chunks
        :param int completed_chunks: completed chunks bitarray
        :param bool completed: if completed
        :param str md5: md5 hex digest
        """
        key = blobxfer.operations.resume._BaseResumeManager.\
            generate_record_key(ase)
        with self.datalock():
            ul = self.get_record(ase, key=key, lock=False)
            if ul is None:
                ul = blobxfer.models.resume.Upload(
                    local_path=str(local_path),
                    length=ase._size,
                    chunk_size=chunk_size,
                    total_chunks=total_chunks,
                    completed_chunks=completed_chunks,
                    completed=completed,
                    md5=md5,
                )
            else:
                if ul.completed or completed_chunks == ul.completed_chunks:
                    return
                ul.completed_chunks = completed_chunks
                if completed:
                    ul.completed = completed
                else:
                    ul.md5hexdigest = md5
            self._data[key] = ul
            self._data.sync()


class SyncCopyResumeManager(_BaseResumeManager):
    """SyncCopy Resume Manager"""
    def __init__(self, resume_file):
        # type: (SyncCopyResumeManager, str) -> None
        """Ctor for SyncCopyResumeManager
        :param SyncCopyResumeManager self: this
        :param pathlib.Path resume_file: resume file
        """
        super(SyncCopyResumeManager, self).__init__(resume_file)

    def add_or_update_record(
            self, dst_ase, src_block_list, offset, chunk_size, total_chunks,
            completed_chunks, completed):
        # type: (SyncCopyResumeManager,
        #        blobxfer.models.azure.StorageEntity, list, int, int, int,
        #        int, bool) -> None
        """Add or update a resume record
        :param SyncCopyResumeManager self: this
        :param blobxfer.models.azure.StorageEntity dst_ase: Storage Entity
        :param list src_block_list: source block list
        :param int offset: offset
        :param int chunk_size: chunk size in bytes
        :param int total_chunks: total chunks
        :param int completed_chunks: completed chunks bitarray
        :param bool completed: if completed
        """
        key = blobxfer.operations.resume._BaseResumeManager.\
            generate_record_key(dst_ase)
        with self.datalock():
            sc = self.get_record(dst_ase, key=key, lock=False)
            if sc is None:
                sc = blobxfer.models.resume.SyncCopy(
                    length=dst_ase._size,
                    src_block_list=src_block_list,
                    offset=offset,
                    chunk_size=chunk_size,
                    total_chunks=total_chunks,
                    completed_chunks=completed_chunks,
                    completed=completed,
                )
            else:
                if sc.completed or completed_chunks == sc.completed_chunks:
                    return
                sc.offset = offset
                sc.completed_chunks = completed_chunks
                if completed:
                    sc.completed = completed
            self._data[key] = sc
            self._data.sync()
