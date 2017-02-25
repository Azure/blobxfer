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
import datetime
import dateutil.tz
import enum
import logging
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
try:
    import queue
except ImportError:  # noqa
    import Queue as queue
import threading
# non-stdlib imports
import dateutil
# local imports
import blobxfer.md5
import blobxfer.models
import blobxfer.operations
import blobxfer.blob.operations
import blobxfer.file.operations
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


class DownloadAction(enum.Enum):
    Skip = 1
    CheckMd5 = 2
    Download = 3


class Downloader(object):
    """Downloader"""
    def __init__(self, general_options, creds, spec):
        # type: (Downloader, blobxfer.models.GeneralOptions,
        #        blobxfer.models.AzureStorageCredentials,
        #        blobxfer.models.DownloadSpecification) -> None
        """Ctor for Downloader
        :param Downloader self: this
        :param blobxfer.models.GeneralOptions general_options: general opts
        :param blobxfer.models.AzureStorageCredentials creds: creds
        :param blobxfer.models.DownloadSpecification spec: download spec
        """
        self._md5_meta_lock = threading.Lock()
        self._download_lock = threading.Lock()
        self._all_remote_files_processed = False
        self._md5_map = {}
        self._md5_offload = None
        self._md5_check_thread = None
        self._download_queue = queue.Queue()
        self._download_set = set()
        self._download_threads = []
        self._download_count = 0
        self._download_total_bytes = 0
        self._download_terminate = False
        self._general_options = general_options
        self._creds = creds
        self._spec = spec

    def _check_download_conditions(self, lpath, rfile):
        # type: (Downloader, pathlib.Path,
        #        blobxfer.models.AzureStorageEntity) -> DownloadAction
        """Check for download conditions
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.AzureStorageEntity rfile: remote file
        :rtype: DownloadAction
        :return: download action
        """
        if not lpath.exists():
            return DownloadAction.Download
        if not self._spec.options.overwrite:
            logger.info(
                'not overwriting local file: {} (remote: {}/{})'.format(
                    lpath, rfile.container, rfile.name))
            return DownloadAction.Skip
        # check skip on options, MD5 match takes priority
        if self._spec.skip_on.md5_match:
            return DownloadAction.CheckMd5
        # if neither of the remaining skip on actions are activated, download
        if (not self._spec.skip_on.filesize_match and
                not self._spec.skip_on.lmt_ge):
            return DownloadAction.Download
        # check skip on file size match
        dl_fs = None
        if self._spec.skip_on.filesize_match:
            lsize = lpath.stat().st_size
            if rfile.mode == blobxfer.models.AzureStorageModes.Page:
                lsize = blobxfer.util.page_align_content_length(lsize)
            if rfile.size == lsize:
                dl_fs = False
            else:
                dl_fs = True
        # check skip on lmt ge
        dl_lmt = None
        if self._spec.skip_on.lmt_ge:
            mtime = datetime.datetime.fromtimestamp(
                lpath.stat().st_mtime, tz=dateutil.tz.tzlocal())
            if mtime >= rfile.lmt:
                dl_lmt = False
            else:
                dl_lmt = True
        # download if either skip on mismatch is True
        if dl_fs or dl_lmt:
            return DownloadAction.Download
        else:
            return DownloadAction.Skip

    def _pre_md5_skip_on_check(self, lpath, rfile):
        # type: (Downloader, pathlib.Path,
        #        blobxfer.models.AzureStorageEntity) -> None
        """Perform pre MD5 skip on check
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.AzureStorageEntity rfile: remote file
        """
        # if encryption metadata is present, check for pre-encryption
        # md5 in blobxfer extensions
        md5 = None
        if rfile.encryption_metadata is not None:
            md5 = rfile.encryption_metadata.blobxfer_extensions.\
                pre_encrypted_content_md5
        if md5 is None:
            md5 = rfile.md5
        slpath = str(lpath)
        with self._md5_meta_lock:
            self._md5_map[slpath] = rfile
        self._md5_offload.add_localfile_for_md5_check(slpath, md5, rfile.mode)

    def _post_md5_skip_on_check(self, filename, md5_match):
        # type: (Downloader, str, bool) -> None
        """Perform post MD5 skip on check
        :param Downloader self: this
        :param str filename: local filename
        :param bool md5_match: if MD5 matches
        """
        with self._md5_meta_lock:
            rfile = self._md5_map.pop(filename)
        lpath = pathlib.Path(filename)
        if md5_match:
            with self._download_lock:
                self._download_set.remove(lpath)
        else:
            self._add_to_download_queue(lpath, rfile)

    def _initialize_check_md5_downloads_thread(self):
        # type: (Downloader) -> None
        """Initialize the md5 done queue check thread
        :param Downloader self: this
        """
        def _check_for_downloads_from_md5(self):
            # type: (Downloader) -> None
            """Check queue for a file to download
            :param Downloader self: this
            """
            cv = self._md5_offload.done_cv
            while True:
                with self._md5_meta_lock:
                    if (self._download_terminate or
                            (len(self._md5_map) == 0 and
                             self._all_remote_files_processed)):
                        break
                result = None
                cv.acquire()
                while not self._download_terminate:
                    result = self._md5_offload.get_localfile_md5_done()
                    if result is None:
                        # use cv timeout due to possible non-wake while running
                        cv.wait(1)
                        # check for terminating conditions
                        with self._md5_meta_lock:
                            if (len(self._md5_map) == 0 and
                                    self._all_remote_files_processed):
                                break
                    else:
                        break
                cv.release()
                if result is not None:
                    self._post_md5_skip_on_check(result[0], result[1])

        self._md5_check_thread = threading.Thread(
            target=_check_for_downloads_from_md5,
            args=(self,)
        )
        self._md5_check_thread.start()

    def _add_to_download_queue(self, lpath, rfile):
        # type: (Downloader, pathlib.Path,
        #        blobxfer.models.AzureStorageEntity) -> None
        """Add remote file to download queue
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.AzureStorageEntity rfile: remote file
        """
        # prepare remote file for download
        dd = blobxfer.models.DownloadDescriptor(
            lpath, rfile, self._spec.options)
        # add download descriptor to queue
        self._download_queue.put(dd)

    def _initialize_download_threads(self):
        # type: (Downloader) -> None
        """Initialize download threads
        :param Downloader self: this
        """
        logger.debug('spawning {} transfer threads'.format(
            self._general_options.concurrency.transfer_threads))
        for _ in range(self._general_options.concurrency.transfer_threads):
            thr = threading.Thread(target=self._worker_thread_download)
            self._download_threads.append(thr)
            thr.start()

    def _wait_for_download_threads(self, terminate):
        # type: (Downloader, bool) -> None
        """Terminate download threads
        :param Downloader self: this
        :param bool terminate: terminate threads
        """
        self._download_terminate = terminate
        for thr in self._download_threads:
            thr.join()

    def _worker_thread_download(self):
        # type: (Downloader) -> None
        """Worker thread download
        :param Downloader self: this
        """
        while True:
            if self._download_terminate:
                break
            with self._download_lock:
                if (self._all_remote_files_processed and
                        len(self._download_set) == 0):
                    break
            try:
                dd = self._download_queue.get(False, 1)
            except queue.Empty:
                continue
            # get download offsets
            offsets = dd.next_offsets()
            # check if all operations completed
            if offsets is None and dd.outstanding_operations == 0:
                # TODO
                # 1. complete integrity checks
                # 2. set file uid/gid
                # 3. set file modes
                # 4. move file to final path
                with self._download_lock:
                    self._download_set.remove(dd.final_path)
                    self._download_count += 1
                logger.info('download complete: {}/{} to {}'.format(
                    dd.entity.container, dd.entity.name, dd.final_path))
                continue
            # re-enqueue for other threads to download
            self._download_queue.put(dd)
            if offsets is None:
                continue
            # issue get range
            if dd.entity.mode == blobxfer.models.AzureStorageModes.File:
                chunk = blobxfer.file.operations.get_file_range(
                    dd.entity, offsets, self._general_options.timeout_sec)
            else:
                chunk = blobxfer.blob.operations.get_blob_range(
                    dd.entity, offsets, self._general_options.timeout_sec)
            # accounting
            with self._download_lock:
                self._download_total_bytes += offsets.num_bytes
            # decrypt if necessary
            if dd.entity.is_encrypted:
                # TODO via crypto pool
                # 1. compute rolling hmac if present
                #    - roll through any subsequent unchecked parts
                # 2. decrypt chunk
                pass
            # compute rolling md5 via md5 pool
            if dd.must_compute_md5:
                # TODO
                # - roll through any subsequent unchecked parts
                pass

            # write data to disk

            # if no integrity check could be performed due to current
            # integrity offset mismatch, add to unchecked set

            dd.dec_outstanding_operations()

            # pickle dd to resume file

#             rfile = dd._ase
#             print('<<', rfile.container, rfile.name, rfile.lmt, rfile.size,
#                   rfile.md5, rfile.mode, rfile.encryption_metadata)

    def _run(self):
        # type: (Downloader) -> None
        """Execute Downloader"""
        # ensure destination path
        blobxfer.operations.ensure_local_destination(self._creds, self._spec)
        logger.info('downloading blobs/files to local path: {}'.format(
            self._spec.destination.path))
        # initialize MD5 processes
        self._md5_offload = blobxfer.md5.LocalFileMd5Offload(
            num_workers=self._general_options.concurrency.md5_processes)
        self._initialize_check_md5_downloads_thread()
        # initialize download threads
        self._initialize_download_threads()
        # iterate through source paths to download
        nfiles = 0
        empty_files = 0
        skipped_files = 0
        total_size = 0
        skipped_size = 0
        for src in self._spec.sources:
            for rfile in src.files(
                    self._creds, self._spec.options, self._general_options):
                nfiles += 1
                total_size += rfile.size
                if rfile.size == 0:
                    empty_files += 1
                # form local path for remote file
                lpath = pathlib.Path(self._spec.destination.path, rfile.name)
                # check on download conditions
                action = self._check_download_conditions(lpath, rfile)
                if action == DownloadAction.Skip:
                    skipped_files += 1
                    skipped_size += rfile.size
                    continue
                # add potential download to set
                with self._download_lock:
                    self._download_set.add(lpath)
                # either MD5 check or download now
                if action == DownloadAction.CheckMd5:
                    self._pre_md5_skip_on_check(lpath, rfile)
                elif action == DownloadAction.Download:
                    self._add_to_download_queue(lpath, rfile)
        download_files = nfiles - skipped_files
        download_size = total_size - skipped_size
        # clean up processes and threads
        with self._md5_meta_lock:
            self._all_remote_files_processed = True
        logger.debug(
            ('{0} remote files processed, waiting for download completion '
             'of {1:.4f} MiB').format(nfiles, download_size / 1048576))
        self._md5_check_thread.join()
        self._wait_for_download_threads(terminate=False)
        self._md5_offload.finalize_md5_processes()
        if (self._download_count != download_files or
                self._download_total_bytes != download_size):
            raise RuntimeError(
                'download mismatch: [count={}/{} bytes={}/{}]'.format(
                    self._download_count, download_files,
                    self._download_total_bytes, download_size))
        logger.info('all files downloaded')

    def start(self):
        # type: (Downloader) -> None
        """Start the Downloader"""
        try:
            self._run()
        except KeyboardInterrupt:
            logger.error(
                'KeyboardInterrupt detected, force terminating '
                'processes and threads (this may take a while)...')
            self._wait_for_download_threads(terminate=True)
            self._md5_offload.finalize_md5_processes()
            # TODO close resume file in finally?
            raise
