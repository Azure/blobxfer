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
import time
# non-stdlib imports
# local imports
import blobxfer.models.crypto
import blobxfer.models.metadata
import blobxfer.operations.azure.blob
import blobxfer.operations.azure.file
import blobxfer.operations.crypto
import blobxfer.operations.md5
import blobxfer.operations.progress
import blobxfer.operations.resume
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_MAX_SINGLE_OBJECT_CONCURRENCY = 8


class DownloadAction(enum.Enum):
    Skip = 1
    CheckMd5 = 2
    Download = 3


class Downloader(object):
    """Downloader"""
    def __init__(self, general_options, creds, spec):
        # type: (Downloader, blobxfer.models.options.General,
        #        blobxfer.operations.azure.StorageCredentials,
        #        blobxfer.models.download.Specification) -> None
        """Ctor for Downloader
        :param Downloader self: this
        :param blobxfer.models.options.General general_options: general opts
        :param blobxfer.operations.azure.StorageCredentials creds: creds
        :param blobxfer.models.download.Specification spec: download spec
        """
        self._all_remote_files_processed = False
        self._crypto_offload = None
        self._md5_meta_lock = threading.Lock()
        self._md5_map = {}
        self._md5_offload = None
        self._transfer_lock = threading.Lock()
        self._transfer_queue = queue.Queue()
        self._transfer_set = set()
        self._transfer_threads = []
        self._transfer_cc = {}
        self._disk_operation_lock = threading.Lock()
        self._disk_queue = queue.Queue()
        self._disk_set = set()
        self._disk_threads = []
        self._download_start_time = None
        self._download_total = 0
        self._download_sofar = 0
        self._download_bytes_total = 0
        self._download_bytes_sofar = 0
        self._download_terminate = False
        self._start_time = None
        self._delete_after = set()
        self._dd_map = {}
        self._vio_map = {}
        self._general_options = general_options
        self._creds = creds
        self._spec = spec
        self._resume = None
        self._exceptions = []

    @property
    def termination_check(self):
        # type: (Downloader) -> bool
        """Check if terminated
        :param Downloader self: this
        :rtype: bool
        :return: if terminated
        """
        with self._transfer_lock:
            with self._disk_operation_lock:
                return (self._download_terminate or
                        len(self._exceptions) > 0 or
                        (self._all_remote_files_processed and
                         len(self._transfer_set) == 0 and
                         len(self._disk_set) == 0))

    @property
    def termination_check_md5(self):
        # type: (Downloader) -> bool
        """Check if terminated from MD5 context
        :param Downloader self: this
        :rtype: bool
        :return: if terminated from MD5 context
        """
        with self._md5_meta_lock:
            with self._transfer_lock:
                return (self._download_terminate or
                        (self._all_remote_files_processed and
                         len(self._md5_map) == 0 and
                         len(self._transfer_set) == 0))

    @staticmethod
    def ensure_local_destination(creds, spec):
        # type: (blobxfer.operations.azure.StorageCredentials,
        #        blobxfer.models.download.Specification) -> None
        """Ensure a local destination path given a download spec
        :param blobxfer.operations.azure.StorageCredentials creds: creds
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
                    if (blobxfer.operations.azure.file.check_if_single_file(
                            sa.file_client, cont, dir)[0] and
                            spec.options.rename):
                        spec.destination.is_dir = False
                else:
                    if (blobxfer.operations.azure.blob.check_if_single_blob(
                            sa.block_blob_client, cont, dir) and
                            spec.options.rename):
                        spec.destination.is_dir = False
        logger.debug('dest is_dir={} for {} specs'.format(
            spec.destination.is_dir, len(spec.sources)))
        # ensure destination path
        spec.destination.ensure_path_exists()

    @staticmethod
    def create_unique_transfer_operation_id(ase):
        # type: (blobxfer.models.azure.StorageEntity) -> str
        """Create a unique transfer operation id
        :param blobxfer.models.azure.StorageEntity ase: storage entity
        :rtype: str
        :return: unique transfer id
        """
        return ';'.join(
            (ase._client.primary_endpoint, ase.path, str(ase.vectored_io))
        )

    @staticmethod
    def create_unique_disk_operation_id(dd, offsets):
        # type: (blobxfer.models.download.Descriptor,
        #        blobxfer.models.download.Offsets) -> str
        """Create a unique disk operation id
        :param blobxfer.models.download.Descriptor dd: download descriptor
        :param blobxfer.models.download.Offsets offsets: download offsets
        :rtype: str
        :return: unique disk id
        """
        return ';'.join(
            (str(dd.final_path), dd.entity._client.primary_endpoint,
             dd.entity.path, str(offsets.range_start))
        )

    def _update_progress_bar(self):
        # type: (Downloader) -> None
        """Update progress bar
        :param Downloader self: this
        """
        blobxfer.operations.progress.update_progress_bar(
            self._general_options,
            'download',
            self._download_start_time,
            self._download_total,
            self._download_sofar,
            self._download_bytes_total,
            self._download_bytes_sofar,
        )

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
            if rfile.vectored_io is not None:
                fpath = blobxfer.models.download.Descriptor.\
                    convert_vectored_io_slice_to_final_path_name(lpath, rfile)
                if not fpath.exists():
                    return DownloadAction.Download
            else:
                return DownloadAction.Download
        if not self._spec.options.overwrite:
            logger.info(
                'not overwriting local file: {} (remote: {})'.format(
                    lpath, rfile.path))
            return DownloadAction.Skip
        # check skip on options, MD5 match takes priority
        md5 = blobxfer.models.metadata.get_md5_from_metadata(rfile)
        if self._spec.skip_on.md5_match and blobxfer.util.is_not_empty(md5):
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
                if self._general_options.verbose:
                    logger.debug('filesize match: {} == {} size={}'.format(
                        lpath, rfile.path, lsize))
            else:
                dl_fs = True
        # check skip on lmt ge
        dl_lmt = None
        if self._spec.skip_on.lmt_ge:
            mtime = blobxfer.util.datetime_from_timestamp(
                lpath.stat().st_mtime, as_utc=True)
            if mtime >= rfile.lmt:
                dl_lmt = False
                if self._general_options.verbose:
                    logger.debug('lmt ge match: {} lmt={} >= {} lmt={}'.format(
                        lpath, mtime, rfile.path, rfile.lmt))
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
        md5 = blobxfer.models.metadata.get_md5_from_metadata(rfile)
        key = blobxfer.operations.download.Downloader.\
            create_unique_transfer_operation_id(rfile)
        with self._md5_meta_lock:
            self._md5_map[key] = rfile
        slpath = str(lpath)
        # temporarily create a download descriptor view for vectored io
        if rfile.vectored_io is not None:
            view, _ = blobxfer.models.download.Descriptor.generate_view(rfile)
            fpath = str(
                blobxfer.models.download.Descriptor.
                convert_vectored_io_slice_to_final_path_name(lpath, rfile)
            )
        else:
            view = None
            fpath = slpath
        self._md5_offload.add_localfile_for_md5_check(
            key, slpath, fpath, md5, rfile.mode, view)

    def _post_md5_skip_on_check(self, key, filename, size, md5_match):
        # type: (Downloader, str, str, int, bool) -> None
        """Perform post MD5 skip on check
        :param Downloader self: this
        :param str key: md5 map key
        :param str filename: local filename
        :param int size: size of checked data
        :param bool md5_match: if MD5 matches
        """
        with self._md5_meta_lock:
            rfile = self._md5_map.pop(key)
        lpath = pathlib.Path(filename)
        if md5_match:
            if size is None:
                size = lpath.stat().st_size
            with self._transfer_lock:
                self._transfer_set.remove(
                    blobxfer.operations.download.Downloader.
                    create_unique_transfer_operation_id(rfile))
                self._download_total -= 1
                self._download_bytes_total -= size
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
                self._post_md5_skip_on_check(
                    result[0], result[1], result[2], result[3])

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
                    cv.wait(0.1)
                    # check for terminating conditions
                    if self.termination_check:
                        break
                else:
                    break
            cv.release()
            if result is not None:
                try:
                    final_path, offsets = result
                    with self._transfer_lock:
                        dd = self._dd_map[final_path]
                    self._finalize_chunk(dd, offsets)
                except KeyError:
                    # this can happen if all of the last integrity
                    # chunks are processed at once
                    pass

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
            lpath, rfile, self._spec.options, self._general_options,
            self._resume)
        if dd.entity.is_encrypted:
            with self._transfer_lock:
                self._dd_map[str(dd.final_path)] = dd
        # add download descriptor to queue
        self._transfer_queue.put(dd)
        if self._download_start_time is None:
            with self._transfer_lock:
                if self._download_start_time is None:
                    self._download_start_time = blobxfer.util.datetime_now()

    def _initialize_disk_threads(self):
        # type: (Downloader) -> None
        """Initialize download threads
        :param Downloader self: this
        """
        logger.debug('spawning {} disk threads'.format(
            self._general_options.concurrency.disk_threads))
        for _ in range(self._general_options.concurrency.disk_threads):
            thr = threading.Thread(target=self._worker_thread_disk)
            self._disk_threads.append(thr)
            thr.start()

    def _initialize_transfer_threads(self):
        # type: (Downloader) -> None
        """Initialize transfer threads
        :param Downloader self: this
        """
        logger.debug('spawning {} transfer threads'.format(
            self._general_options.concurrency.transfer_threads))
        for _ in range(self._general_options.concurrency.transfer_threads):
            thr = threading.Thread(target=self._worker_thread_transfer)
            self._transfer_threads.append(thr)
            thr.start()

    def _wait_for_disk_threads(self, terminate):
        # type: (Downloader, bool) -> None
        """Wait for disk threads
        :param Downloader self: this
        :param bool terminate: terminate threads
        """
        if terminate:
            self._download_terminate = terminate
        for thr in self._disk_threads:
            blobxfer.util.join_thread(thr)

    def _wait_for_transfer_threads(self, terminate):
        # type: (Downloader, bool) -> None
        """Wait for download threads
        :param Downloader self: this
        :param bool terminate: terminate threads
        """
        if terminate:
            self._download_terminate = terminate
        for thr in self._transfer_threads:
            blobxfer.util.join_thread(thr)

    def _worker_thread_transfer(self):
        # type: (Downloader) -> None
        """Worker thread download
        :param Downloader self: this
        """
        max_set_len = self._general_options.concurrency.disk_threads << 2
        while not self.termination_check:
            try:
                if len(self._disk_set) > max_set_len:
                    time.sleep(0.1)
                    continue
                else:
                    dd = self._transfer_queue.get(block=False, timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._process_download_descriptor(dd)
            except Exception as e:
                with self._transfer_lock:
                    self._exceptions.append(e)

    def _worker_thread_disk(self):
        # type: (Downloader) -> None
        """Worker thread for disk
        :param Downloader self: this
        """
        while not self.termination_check:
            try:
                dd, offsets, data = self._disk_queue.get(
                    block=False, timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._process_data(dd, offsets, data)
            except Exception as e:
                with self._transfer_lock:
                    self._exceptions.append(e)

    def _process_download_descriptor(self, dd):
        # type: (Downloader, blobxfer.models.download.Descriptor) -> None
        """Process download descriptor
        :param Downloader self: this
        :param blobxfer.models.download.Descriptor dd: download descriptor
        """
        # update progress bar
        self._update_progress_bar()
        # get download offsets
        offsets, resume_bytes = dd.next_offsets()
        # add resume bytes to counter
        if resume_bytes is not None:
            with self._disk_operation_lock:
                self._download_bytes_sofar += resume_bytes
                logger.debug('adding {} sofar {} from {}'.format(
                    resume_bytes, self._download_bytes_sofar, dd.entity.name))
            del resume_bytes
        # check if all operations completed
        if offsets is None and dd.all_operations_completed:
            finalize = True
            sfpath = str(dd.final_path)
            # finalize integrity
            dd.finalize_integrity()
            # vectored io checks
            if dd.entity.vectored_io is not None:
                with self._transfer_lock:
                    if sfpath not in self._vio_map:
                        self._vio_map[sfpath] = 1
                    else:
                        self._vio_map[sfpath] += 1
                    if (self._vio_map[sfpath] ==
                            dd.entity.vectored_io.total_slices):
                        self._vio_map.pop(sfpath)
                    else:
                        finalize = False
            # finalize file
            if finalize:
                dd.finalize_file()
            # accounting
            with self._transfer_lock:
                self._download_sofar += 1
                if dd.entity.is_encrypted:
                    self._dd_map.pop(sfpath)
                self._transfer_set.remove(
                    blobxfer.operations.download.Downloader.
                    create_unique_transfer_operation_id(dd.entity))
                self._transfer_cc.pop(dd.final_path, None)
            return
        # re-enqueue for other threads to download
        if offsets is None:
            self._transfer_queue.put(dd)
            return
        # check if there are too many concurrent connections
        with self._transfer_lock:
            if dd.final_path not in self._transfer_cc:
                self._transfer_cc[dd.final_path] = 0
            self._transfer_cc[dd.final_path] += 1
            cc_xfer = self._transfer_cc[dd.final_path]
        if cc_xfer <= _MAX_SINGLE_OBJECT_CONCURRENCY:
            self._transfer_queue.put(dd)
        # issue get range
        if dd.entity.mode == blobxfer.models.azure.StorageModes.File:
            data = blobxfer.operations.azure.file.get_file_range(
                dd.entity, offsets)
        else:
            data = blobxfer.operations.azure.blob.get_blob_range(
                dd.entity, offsets)
        with self._transfer_lock:
            self._transfer_cc[dd.final_path] -= 1
        if cc_xfer > _MAX_SINGLE_OBJECT_CONCURRENCY:
            self._transfer_queue.put(dd)
        # enqueue data for processing
        with self._disk_operation_lock:
            self._disk_set.add(
                blobxfer.operations.download.Downloader.
                create_unique_disk_operation_id(dd, offsets))
        self._disk_queue.put((dd, offsets, data))

    def _process_data(self, dd, offsets, data):
        # type: (Downloader, blobxfer.models.download.Descriptor,
        #        blobxfer.models.download.Offsets, bytes) -> None
        """Process downloaded data for disk
        :param Downloader self: this
        :param blobxfer.models.download.Descriptor dd: download descriptor
        :param blobxfer.models.download.Offsets offsets: offsets
        :param bytes data: data to process
        """
        # decrypt if necessary
        if dd.entity.is_encrypted:
            # slice data to proper bounds and get iv for chunk
            if offsets.chunk_num == 0:
                # set iv
                iv = dd.entity.encryption_metadata.content_encryption_iv
                # set data to decrypt
                encdata = data
                # send iv through hmac
                dd.hmac_iv(iv)
            else:
                # set iv
                iv = data[:blobxfer.models.crypto.AES256_BLOCKSIZE_BYTES]
                # set data to decrypt
                encdata = data[blobxfer.models.crypto.AES256_BLOCKSIZE_BYTES:]
            # write encdata to disk for hmac later
            _hmac_datafile = dd.write_unchecked_hmac_data(
                offsets, encdata)
            # decrypt data
            if self._crypto_offload is not None:
                self._crypto_offload.add_decrypt_chunk(
                    str(dd.final_path), dd.view.fd_start, offsets,
                    dd.entity.encryption_metadata.symmetric_key,
                    iv, _hmac_datafile)
                # data will be integrity checked and written once
                # retrieved from crypto queue
                return
            else:
                data = blobxfer.operations.crypto.aes_cbc_decrypt_data(
                    dd.entity.encryption_metadata.symmetric_key,
                    iv, encdata, offsets.unpad)
                dd.write_data(offsets, data)
        else:
            # write data to disk
            dd.write_unchecked_data(offsets, data)
        # finalize chunk
        self._finalize_chunk(dd, offsets)

    def _finalize_chunk(self, dd, offsets):
        # type: (Downloader, blobxfer.models.download.Descriptor,
        #        blobxfer.models.download.Offsets) -> None
        """Finalize written chunk
        :param Downloader self: this
        :param blobxfer.models.download.Descriptor dd: download descriptor
        :param blobxfer.models.download.Offsets offsets: offsets
        """
        if dd.entity.is_encrypted:
            dd.mark_unchecked_chunk_decrypted(offsets.chunk_num)
        # integrity check data and write to disk (this is called
        # regardless of md5/hmac enablement for resume purposes)
        dd.perform_chunked_integrity_check()
        # remove from disk set and add bytes to counter
        with self._disk_operation_lock:
            self._disk_set.remove(
                blobxfer.operations.download.Downloader.
                create_unique_disk_operation_id(dd, offsets))
            self._download_bytes_sofar += offsets.num_bytes

    def _cleanup_temporary_files(self):
        # type: (Downloader) -> None
        """Cleanup temporary files in case of an exception or interrupt.
        This function is not thread-safe.
        :param Downloader self: this
        """
        # iterate through dd map and cleanup files
        for key in self._dd_map:
            dd = self._dd_map[key]
            try:
                dd.cleanup_all_temporary_files()
            except Exception as e:
                logger.exception(e)

    def _catalog_local_files_for_deletion(self):
        # type: (Downloader) -> None
        """Catalog all local files if delete extraneous enabled
        :param Downloader self: this
        """
        if not (self._spec.options.delete_extraneous_destination and
                self._spec.destination.is_dir):
            return
        dst = str(self._spec.destination.path)
        for file in blobxfer.util.scantree(dst):
            self._delete_after.add(pathlib.Path(file.path))

    def _delete_extraneous_files(self):
        # type: (Downloader) -> None
        """Delete extraneous files cataloged
        :param Downloader self: this
        """
        logger.info('attempting to delete {} extraneous files'.format(
            len(self._delete_after)))
        for file in self._delete_after:
            if self._general_options.verbose:
                logger.debug('deleting local file: {}'.format(file))
            try:
                file.unlink()
            except OSError as e:
                logger.error('error deleting local file: {}'.format(str(e)))

    def _run(self):
        # type: (Downloader) -> None
        """Execute Downloader
        :param Downloader self: this
        """
        # mark start
        self._start_time = blobxfer.util.datetime_now()
        logger.info('blobxfer start time: {0}'.format(self._start_time))
        # ensure destination path
        blobxfer.operations.download.Downloader.ensure_local_destination(
            self._creds, self._spec)
        logger.info('downloading blobs/files to local path: {}'.format(
            self._spec.destination.path))
        self._catalog_local_files_for_deletion()
        # initialize resume db if specified
        if self._general_options.resume_file is not None:
            self._resume = blobxfer.operations.resume.DownloadResumeManager(
                self._general_options.resume_file)
        # initialize MD5 processes
        if (self._spec.options.check_file_md5 and
                self._general_options.concurrency.md5_processes > 0):
            self._md5_offload = blobxfer.operations.md5.LocalFileMd5Offload(
                num_workers=self._general_options.concurrency.md5_processes)
            self._md5_offload.initialize_check_thread(
                self._check_for_downloads_from_md5)
        # initialize crypto processes
        if self._general_options.concurrency.crypto_processes > 0:
            self._crypto_offload = blobxfer.operations.crypto.CryptoOffload(
                num_workers=self._general_options.concurrency.crypto_processes)
            self._crypto_offload.initialize_check_thread(
                self._check_for_crypto_done)
        # initialize download threads
        self._initialize_transfer_threads()
        self._initialize_disk_threads()
        # initialize local counters
        skipped_files = 0
        skipped_size = 0
        # iterate through source paths to download
        for src in self._spec.sources:
            for rfile in src.files(self._creds, self._spec.options):
                # form local path for remote file
                if (not self._spec.destination.is_dir and
                        self._spec.options.rename):
                    lpath = pathlib.Path(self._spec.destination.path)
                else:
                    lpath = None
                    if self._spec.options.strip_components > 0:
                        _lparts = pathlib.Path(rfile.name).parts
                        _strip = min(
                            (len(_lparts) - 1,
                             self._spec.options.strip_components)
                        )
                        if _strip > 0:
                            lpath = pathlib.Path(*_lparts[_strip:])
                    if lpath is None:
                        lpath = pathlib.Path(rfile.name)
                    lpath = pathlib.Path(self._spec.destination.path) / lpath
                # check on download conditions
                action = self._check_download_conditions(lpath, rfile)
                # remove from delete after set
                try:
                    self._delete_after.remove(lpath)
                except KeyError:
                    pass
                if action == DownloadAction.Skip:
                    skipped_files += 1
                    skipped_size += rfile.size
                    continue
                # add potential download to set
                with self._transfer_lock:
                    self._transfer_set.add(
                        blobxfer.operations.download.Downloader.
                        create_unique_transfer_operation_id(rfile))
                    self._download_total += 1
                    self._download_bytes_total += rfile.size
                # either MD5 check or download now
                if action == DownloadAction.CheckMd5:
                    self._pre_md5_skip_on_check(lpath, rfile)
                elif action == DownloadAction.Download:
                    self._add_to_download_queue(lpath, rfile)
        # set remote files processed
        with self._md5_meta_lock:
            self._all_remote_files_processed = True
        with self._transfer_lock:
            download_size_mib = (
                self._download_bytes_total / blobxfer.util.MEGABYTE
            )
            logger.debug(
                ('{0} files {1:.4f} MiB filesize and/or lmt_ge '
                 'skipped').format(
                    skipped_files, skipped_size / blobxfer.util.MEGABYTE))
            logger.debug(
                ('{0} remote files processed, waiting for download '
                 'completion of approx. {1:.4f} MiB').format(
                     self._download_total, download_size_mib))
        del skipped_files
        del skipped_size
        # wait for downloads to complete
        self._wait_for_transfer_threads(terminate=False)
        self._wait_for_disk_threads(terminate=False)
        end_time = blobxfer.util.datetime_now()
        # update progress bar
        self._update_progress_bar()
        # check for exceptions
        if len(self._exceptions) > 0:
            logger.error('exceptions encountered while downloading')
            # raise the first one
            raise self._exceptions[0]
        # check for mismatches
        if (self._download_sofar != self._download_total or
                self._download_bytes_sofar != self._download_bytes_total):
            raise RuntimeError(
                'download mismatch: [count={}/{} bytes={}/{}]'.format(
                    self._download_sofar, self._download_total,
                    self._download_bytes_sofar, self._download_bytes_total))
        # delete all remaining local files not accounted for if
        # delete extraneous enabled
        self._delete_extraneous_files()
        # delete resume file if we've gotten this far
        if self._resume is not None:
            self._resume.delete()
        # output throughput
        if self._download_start_time is not None:
            dltime = (end_time - self._download_start_time).total_seconds()
            download_size_mib = (
                self._download_bytes_total / blobxfer.util.MEGABYTE
            )
            dlmibspeed = download_size_mib / dltime
            logger.info(
                ('elapsed download + verify time and throughput of {0:.4f} '
                 'GiB: {1:.3f} sec, {2:.4f} Mbps ({3:.3f} MiB/sec)').format(
                     download_size_mib / 1024, dltime, dlmibspeed * 8,
                     dlmibspeed))
        end_time = blobxfer.util.datetime_now()
        logger.info('blobxfer end time: {0} (elapsed: {1:.3f} sec)'.format(
            end_time, (end_time - self._start_time).total_seconds()))

    def start(self):
        # type: (Downloader) -> None
        """Start the Downloader
        :param Downloader self: this
        """
        try:
            blobxfer.operations.progress.output_parameters(
                self._general_options, self._spec)
            self._run()
        except (KeyboardInterrupt, Exception) as ex:
            if isinstance(ex, KeyboardInterrupt):
                logger.info(
                    'KeyboardInterrupt detected, force terminating '
                    'processes and threads (this may take a while)...')
            else:
                logger.exception(ex)
            try:
                self._wait_for_disk_threads(terminate=True)
                self._wait_for_transfer_threads(terminate=True)
            finally:
                self._cleanup_temporary_files()
            if not isinstance(ex, KeyboardInterrupt):
                raise
        finally:
            # shutdown processes
            if self._md5_offload is not None:
                self._md5_offload.finalize_processes()
            if self._crypto_offload is not None:
                self._crypto_offload.finalize_processes()
            # close resume file
            if self._resume is not None:
                self._resume.close()
