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
import blobxfer.models.crypto
import blobxfer.models.md5
import blobxfer.operations.azure.blob
import blobxfer.operations.azure.file
import blobxfer.operations.crypto
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
        # type: (Downloader, blobxfer.models.options.General,
        #        blobxfer.models.azure.StorageCredentials,
        #        blobxfer.models.download.Specification) -> None
        """Ctor for Downloader
        :param Downloader self: this
        :param blobxfer.models.options.General general_options: general opts
        :param blobxfer.models.azure.StorageCredentials creds: creds
        :param blobxfer.models.download.Specification spec: download spec
        """
        self._all_remote_files_processed = False
        self._crypto_offload = None
        self._md5_meta_lock = threading.Lock()
        self._md5_map = {}
        self._md5_offload = None
        self._download_lock = threading.Lock()
        self._download_queue = queue.Queue()
        self._download_set = set()
        self._download_start = None
        self._download_threads = []
        self._download_count = 0
        self._download_total_bytes = 0
        self._download_terminate = False
        self._dd_map = {}
        self._general_options = general_options
        self._creds = creds
        self._spec = spec

    @property
    def termination_check(self):
        # type: (Downloader) -> bool
        """Check if terminated
        :param Downloader self: this
        :rtype: bool
        :return: if terminated
        """
        with self._download_lock:
            return (self._download_terminate or
                    (self._all_remote_files_processed and
                     len(self._download_set) == 0))

    @property
    def termination_check_md5(self):
        # type: (Downloader) -> bool
        """Check if terminated from MD5 context
        :param Downloader self: this
        :rtype: bool
        :return: if terminated from MD5 context
        """
        with self._md5_meta_lock:
            with self._download_lock:
                return (self._download_terminate or
                        (self._all_remote_files_processed and
                         len(self._md5_map) == 0 and
                         len(self._download_set) == 0))

    @staticmethod
    def ensure_local_destination(creds, spec):
        # type: (blobxfer.models.azure.StorageCredentials,
        #        blobxfer.models.download.Specification) -> None
        """Ensure a local destination path given a download spec
        :param blobxfer.models.azure.StorageCredentials creds: creds
        :param blobxfer.models.download.Specification spec: download spec
        """
        # ensure destination path is writable given the source
        if len(spec.sources) < 1:
            raise RuntimeError('no sources to download from specified')
        # set is_dir for destination
        spec.destination.is_dir = True
        if len(spec.sources) == 1:
            # we need to query the source to see if this is a directory
            rpath = str(spec.sources[0].paths[0])
            cont, dir = blobxfer.util.explode_azure_path(rpath)
            if not blobxfer.util.is_none_or_empty(dir):
                sa = creds.get_storage_account(
                    spec.sources[0].lookup_storage_account(rpath))
                if (spec.options.mode ==
                        blobxfer.models.azure.StorageModes.File):
                    if blobxfer.operations.azure.file.check_if_single_file(
                            sa.file_client, cont, dir)[0]:
                        spec.destination.is_dir = False
                else:
                    if blobxfer.operations.azure.blob.check_if_single_blob(
                            sa.block_blob_client, cont, dir):
                        spec.destination.is_dir = False
        logger.debug('dest is_dir={} for {} specs'.format(
            spec.destination.is_dir, len(spec.sources)))
        # ensure destination path
        spec.destination.ensure_path_exists()

    def _check_download_conditions(self, lpath, rfile):
        # type: (Downloader, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity) -> DownloadAction
        """Check for download conditions
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.azure.StorageEntity rfile: remote file
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
            if rfile.mode == blobxfer.models.azure.StorageModes.Page:
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
        #        blobxfer.models.azure.StorageEntity) -> None
        """Perform pre MD5 skip on check
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.azure.StorageEntity rfile: remote file
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

    def _check_for_downloads_from_md5(self):
        # type: (Downloader) -> None
        """Check queue for a file to download
        :param Downloader self: this
        """
        cv = self._md5_offload.done_cv
        while not self.termination_check_md5:
            result = None
            cv.acquire()
            while True:
                result = self._md5_offload.pop_done_queue()
                if result is None:
                    # use cv timeout due to possible non-wake while running
                    cv.wait(1)
                    # check for terminating conditions
                    if self.termination_check_md5:
                        break
                else:
                    break
            cv.release()
            if result is not None:
                self._post_md5_skip_on_check(result[0], result[1])

    def _check_for_crypto_done(self):
        # type: (Downloader) -> None
        """Check queue for crypto done
        :param Downloader self: this
        """
        cv = self._crypto_offload.done_cv
        while not self.termination_check:
            result = None
            cv.acquire()
            while True:
                result = self._crypto_offload.pop_done_queue()
                if result is None:
                    # use cv timeout due to possible non-wake while running
                    cv.wait(1)
                    # check for terminating conditions
                    if self.termination_check:
                        break
                else:
                    break
            cv.release()
            if result is not None:
                with self._download_lock:
                    dd = self._dd_map[result[0]]
                self._complete_chunk_download(result[1], result[2], dd)

    def _add_to_download_queue(self, lpath, rfile):
        # type: (Downloader, pathlib.Path,
        #        blobxfer.models.azure.StorageEntity) -> None
        """Add remote file to download queue
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.azure.StorageEntity rfile: remote file
        """
        # prepare remote file for download
        dd = blobxfer.models.download.Descriptor(
            lpath, rfile, self._spec.options)
        if dd.entity.is_encrypted:
            with self._download_lock:
                self._dd_map[str(dd.final_path)] = dd
        # add download descriptor to queue
        self._download_queue.put(dd)
        if self._download_start is None:
            with self._download_lock:
                if self._download_start is None:
                    self._download_start = datetime.datetime.now(
                        tz=dateutil.tz.tzlocal())

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
        if terminate:
            self._download_terminate = terminate
        for thr in self._download_threads:
            thr.join()

    def _worker_thread_download(self):
        # type: (Downloader) -> None
        """Worker thread download
        :param Downloader self: this
        """
        while not self.termination_check:
            try:
                dd = self._download_queue.get(False, 1)
            except queue.Empty:
                continue
            # get download offsets
            offsets = dd.next_offsets()
            # check if all operations completed
            if offsets is None and dd.all_operations_completed:
                # finalize file
                dd.finalize_file()
                # accounting
                with self._download_lock:
                    if dd.entity.is_encrypted:
                        self._dd_map.pop(str(dd.final_path))
                    self._download_set.remove(dd.final_path)
                    self._download_count += 1
                continue
            # re-enqueue for other threads to download
            self._download_queue.put(dd)
            if offsets is None:
                continue
            # issue get range
            if dd.entity.mode == blobxfer.models.azure.StorageModes.File:
                data = blobxfer.operations.azure.file.get_file_range(
                    dd.entity, offsets, self._general_options.timeout_sec)
            else:
                data = blobxfer.operations.azure.blob.get_blob_range(
                    dd.entity, offsets, self._general_options.timeout_sec)
            # accounting
            with self._download_lock:
                self._download_total_bytes += offsets.num_bytes
            # decrypt if necessary
            if dd.entity.is_encrypted:
                # slice data to proper bounds
                encdata = data[blobxfer.models.crypto._AES256_BLOCKSIZE_BYTES:]
                intdata = encdata
                # get iv for chunk and compute hmac
                if offsets.chunk_num == 0:
                    iv = dd.entity.encryption_metadata.content_encryption_iv
                    # integrity check for first chunk must include iv
                    intdata = iv + data
                else:
                    iv = data[:blobxfer.models.crypto._AES256_BLOCKSIZE_BYTES]
                # integrity check data
                dd.perform_chunked_integrity_check(offsets, intdata)
                # decrypt data
                if self._crypto_offload is not None:
                    self._crypto_offload.add_decrypt_chunk(
                        str(dd.final_path), offsets,
                        dd.entity.encryption_metadata.symmetric_key,
                        iv, encdata)
                    # data will be completed once retrieved from crypto queue
                    continue
                else:
                    data = blobxfer.operations.crypto.aes_cbc_decrypt_data(
                        dd.entity.encryption_metadata.symmetric_key,
                        iv, encdata, offsets.unpad)
            elif dd.must_compute_md5:
                # rolling compute md5
                dd.perform_chunked_integrity_check(offsets, data)
            # complete chunk download
            self._complete_chunk_download(offsets, data, dd)

    def _complete_chunk_download(self, offsets, data, dd):
        # type: (Downloader, blobxfer.models.download.Offsets, bytes,
        #        blobxfer.models.download.Descriptor) -> None
        """Complete chunk download
        :param Downloader self: this
        :param blobxfer.models.download.Offsets offsets: offsets
        :param bytes data: data
        :param blobxfer.models.download.Descriptor dd: download descriptor
        """
        # write data to disk
        dd.write_data(offsets, data)
        # decrement outstanding operations
        dd.dec_outstanding_operations()
        # TODO pickle dd to resume file

    def _cleanup_temporary_files(self):
        # type: (Downloader) -> None
        """Cleanup temporary files in case of an exception or interrupt.
        This function is not thread-safe.
        :param Downloader self: this
        """
        # do not clean up if resume file exists
        if self._general_options.resume_file is not None:
            logger.debug(
                'not cleaning up temporary files since resume file has '
                'been specified')
            return
        # iterate through dd map and cleanup files
        for key in self._dd_map:
            dd = self._dd_map[key]
            try:
                dd.cleanup_all_temporary_files()
            except Exception as e:
                logger.exception(e)

    def _run(self):
        # type: (Downloader) -> None
        """Execute Downloader"""
        start_time = datetime.datetime.now(tz=dateutil.tz.tzlocal())
        logger.info('script start time: {0}'.format(start_time))
        # ensure destination path
        blobxfer.operations.download.Downloader.ensure_local_destination(
            self._creds, self._spec)
        logger.info('downloading blobs/files to local path: {}'.format(
            self._spec.destination.path))
        # initialize MD5 processes
        self._md5_offload = blobxfer.models.md5.LocalFileMd5Offload(
            num_workers=self._general_options.concurrency.md5_processes)
        self._md5_offload.initialize_check_thread(
            self._check_for_downloads_from_md5)
        # initialize crypto processes
        if self._general_options.concurrency.crypto_processes > 0:
            self._crypto_offload = blobxfer.models.crypto.CryptoOffload(
                num_workers=self._general_options.concurrency.crypto_processes)
            self._crypto_offload.initialize_check_thread(
                self._check_for_crypto_done)
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
        download_size_mib = download_size / 1048576
        # clean up processes and threads
        with self._md5_meta_lock:
            self._all_remote_files_processed = True
        logger.debug(
            ('{0} remote files processed, waiting for download completion '
             'of {1:.4f} MiB').format(nfiles, download_size_mib))
        self._wait_for_download_threads(terminate=False)
        end_time = datetime.datetime.now(tz=dateutil.tz.tzlocal())
        if (self._download_count != download_files or
                self._download_total_bytes != download_size):
            raise RuntimeError(
                'download mismatch: [count={}/{} bytes={}/{}]'.format(
                    self._download_count, download_files,
                    self._download_total_bytes, download_size))
        if self._download_start is not None:
            dltime = (end_time - self._download_start).total_seconds()
            logger.info(
                ('elapsed download + verify time and throughput: {0:.3f} sec, '
                 '{1:.4f} Mbps').format(
                     dltime, download_size_mib * 8 / dltime))
        logger.info('script end time: {0} (elapsed: {1:.3f} sec)'.format(
            end_time, (end_time - start_time).total_seconds()))

    def start(self):
        # type: (Downloader) -> None
        """Start the Downloader"""
        try:
            self._run()
        except (KeyboardInterrupt, Exception) as ex:
            if isinstance(ex, KeyboardInterrupt):
                logger.error(
                    'KeyboardInterrupt detected, force terminating '
                    'processes and threads (this may take a while)...')
            self._wait_for_download_threads(terminate=True)
            self._cleanup_temporary_files()
            raise
        finally:
            # TODO close resume file
            # shutdown processes
            if self._md5_offload is not None:
                self._md5_offload.finalize_processes()
            if self._crypto_offload is not None:
                self._crypto_offload.finalize_processes()
