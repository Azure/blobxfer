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
except ImportError:
    import pathlib
import threading
# non-stdlib imports
import dateutil
# local imports
import blobxfer.md5
import blobxfer.operations
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
        self._all_remote_files_processed = False
        self._md5_map = {}
        self._md5_offload = None
        self._md5_check_thread = None
        self._general_options = general_options
        self._creds = creds
        self._spec = spec

    def _check_download_conditions(self, lpath, rfile, spec):
        # type: (Downloader, pathlib.Path, blobxfer.models.AzureStorageEntity,
        #        blobxfer.models.DownloadSpecification) -> DownloadAction
        """Check for download conditions
        :param Downloader self: this
        :param pathlib.Path lpath: local path
        :param blobxfer.models.AzureStorageEntity rfile: remote file
        :param blobxfer.models.DownloadSpecification spec: download spec
        :rtype: DownloadAction
        :return: download action
        """
        if not lpath.exists():
            return DownloadAction.Download
        if not spec.options.overwrite:
            logger.info(
                'not overwriting local file: {} (remote: {}/{})'.format(
                    lpath, rfile.container, rfile.name))
            return DownloadAction.Skip
        # check skip on options, MD5 match takes priority
        if spec.skip_on.md5_match:
            return DownloadAction.CheckMd5
        # if neither of the remaining skip on actions are activated, download
        if not spec.skip_on.filesize_match and not spec.skip_on.lmt_ge:
            return DownloadAction.Download
        # check skip on file size match
        dl_fs = None
        if spec.skip_on.filesize_match:
            lsize = lpath.stat().st_size
            if rfile.mode == blobxfer.models.AzureStorageModes.Page:
                lsize = blobxfer.util.page_align_content_length(lsize)
            if rfile.size == lsize:
                dl_fs = False
            else:
                dl_fs = True
        # check skip on lmt ge
        dl_lmt = None
        if spec.skip_on.lmt_ge:
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
        if not md5_match:
            lpath = pathlib.Path(filename)
            # TODO enqueue file for download
        with self._md5_meta_lock:
            self._md5_map.pop(filename)

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
                    if (len(self._md5_map) == 0 and
                            self._all_remote_files_processed):
                        break
                cv.acquire()
                while True:
                    result = self._md5_offload.get_localfile_md5_done()
                    if result is None:
                        # use cv timeout due to possible non-wake while running
                        cv.wait(1)
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

    def start(self):
        # type: (None) -> None
        """Start Downloader"""
        # ensure destination path
        blobxfer.operations.ensure_local_destination(self._creds, self._spec)
        logger.info('downloading blobs/files to local path: {}'.format(
            self._spec.destination.path))
        # initialize MD5 processes
        self._md5_offload = blobxfer.md5.LocalFileMd5Offload()
        self._initialize_check_md5_downloads_thread()
        # iterate through source paths to download
        for src in self._spec.sources:
            for rfile in src.files(
                    self._creds, self._spec.options, self._general_options):
                # form local path for remote file
                lpath = pathlib.Path(self._spec.destination.path, rfile.name)
                # check on download conditions
                action = self._check_download_conditions(
                    lpath, rfile, self._spec)
                if action == DownloadAction.Skip:
                    continue
                elif action == DownloadAction.CheckMd5:
                    self._pre_md5_skip_on_check(lpath, rfile)
                elif action == DownloadAction.Download:
                    # TODO add to download queue
                    pass
                # cond checks?
                print(rfile.container, rfile.name, rfile.lmt, rfile.size,
                      rfile.md5, rfile.mode, rfile.encryption_metadata)

        # clean up processes and threads
        with self._md5_meta_lock:
            self._all_remote_files_processed = True
        self._md5_check_thread.join()
        self._md5_offload.finalize_md5_processes()
