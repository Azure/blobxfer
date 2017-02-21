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

# global defines
_MD5_MAP = {}
_MD5_META_LOCK = threading.Lock()
_ALL_REMOTE_FILES_PROCESSED = False


class DownloadAction(enum.Enum):
    Skip = 1
    CheckMd5 = 2
    Download = 3


def _check_download_conditions(lpath, rfile, spec):
    # type: (pathlib.Path, blobxfer.models.AzureStorageEntity,
    #        blobxfer.models.DownloadSpecification) -> DownloadAction
    """Check for download conditions
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


def pre_md5_skip_on_check(lpath, rfile):
    # type: (pathlib.Path, blobxfer.models.AzureStorageEntity) -> None
    """Perform pre MD5 skip on check
    :param pathlib.Path lpath: local path
    :param blobxfer.models.AzureStorageEntity rfile: remote file
    """
    global _MD5_META_LOCK, _MD5_MAP
    # if encryption metadata is present, check for pre-encryption
    # md5 in blobxfer extensions
    md5 = None
    if rfile.encryption_metadata is not None:
        md5 = rfile.encryption_metadata.blobxfer_extensions.\
            pre_encrypted_content_md5
    if md5 is None:
        md5 = rfile.md5
    slpath = str(lpath)
    with _MD5_META_LOCK:
        _MD5_MAP[slpath] = rfile
        print('pre', lpath, len(_MD5_MAP))
    blobxfer.md5.add_file_for_md5_check(
        slpath, md5, rfile.mode)


def post_md5_skip_on_check(filename, md5_match):
    # type: (str, bool) -> None
    """Perform post MD5 skip on check
    :param str filename: local filename
    :param bool md5_match: if MD5 matches
    """
    global _MD5_META_LOCK, _MD5_MAP
    if not md5_match:
        lpath = pathlib.Path(filename)
        # TODO enqueue file for download
    with _MD5_META_LOCK:
        _MD5_MAP.pop(filename)


def check_md5_downloads_thread():
    def check_for_downloads_from_md5():
        # type: (None) -> str
        """Check queue for a file to download
        :rtype: str
        :return: local file path
        """
        global _MD5_META_LOCK, _MD5_MAP, _ALL_REMOTE_FILES_PROCESSED
        cv = blobxfer.md5.get_done_cv()
        while True:
            with _MD5_META_LOCK:
                if len(_MD5_MAP) == 0 and _ALL_REMOTE_FILES_PROCESSED:
                    break
            cv.acquire()
            while True:
                result = blobxfer.md5.check_md5_file_for_download()
                if result is None:
                    # use cv timeout due to possible non-wake while running
                    cv.wait(1)
                else:
                    break
            cv.release()
            if result is not None:
                post_md5_skip_on_check(result[0], result[1])

    thr = threading.Thread(target=check_for_downloads_from_md5)
    thr.start()
    return thr


def download(general_options, creds, spec):
    # type: (blobxfer.models.GeneralOptions,
    #        blobxfer.models.AzureStorageCredentials,
    #        blobxfer.models.DownloadSpecification) -> None
    """Download action
    :param blobxfer.models.GeneralOptions general_options: general opts
    :param blobxfer.models.AzureStorageCredentials creds: creds
    :param blobxfer.models.DownloadSpecification spec: download spec
    """
    # ensure destination path
    blobxfer.operations.ensure_local_destination(creds, spec)
    logger.info('downloading to local path: {}'.format(spec.destination.path))
    # initialize MD5 processes
    blobxfer.md5.initialize_md5_processes()
    md5_thread = check_md5_downloads_thread()
    # iterate through source paths to download
    for src in spec.sources:
        for rfile in src.files(creds, spec.options, general_options):
            # form local path for remote file
            lpath = pathlib.Path(spec.destination.path, rfile.name)
            # check on download conditions
            action = _check_download_conditions(lpath, rfile, spec)
            if action == DownloadAction.Skip:
                continue
            elif action == DownloadAction.CheckMd5:
                pre_md5_skip_on_check(lpath, rfile)
            elif action == DownloadAction.Download:
                # add to download queue
                ### TODO
                pass
            # cond checks?
            print(rfile.container, rfile.name, rfile.lmt, rfile.size,
                  rfile.md5, rfile.mode, rfile.encryption_metadata)

    global _MD5_META_LOCK, _ALL_REMOTE_FILES_PROCESSED
    with _MD5_META_LOCK:
        _ALL_REMOTE_FILES_PROCESSED = True
    md5_thread.join()
    blobxfer.md5.finalize_md5_processes()

    import time
    time.sleep(5)

