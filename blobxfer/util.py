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
import base64
import copy
import datetime
import hashlib
import logging
import logging.handlers
import mimetypes
try:
    from os import scandir as scandir
except ImportError:  # noqa
    from scandir import scandir as scandir
import platform
import re
# non-stdlib imports
import dateutil.parser
import dateutil.tz
import future.utils
# local imports

# global defines
MEGABYTE = 1048576
_ON_WINDOWS = platform.system() == 'Windows'
_REGISTERED_LOGGER_HANDLERS = []
_PAGEBLOB_BOUNDARY = 512


def on_python2():
    # type: (None) -> bool
    """Execution on python2
    :rtype: bool
    :return: if on Python2
    """
    return future.utils.PY2


def on_windows():  # noqa
    # type: (None) -> bool
    """Execution on Windows
    :rtype: bool
    :return: if on Windows
    """
    return _ON_WINDOWS


def setup_logger(logger, logfile):  # noqa
    # type: (logger, str) -> None
    """Set up logger"""
    global _REGISTERED_LOGGER_HANDLERS
    logger.setLevel(logging.DEBUG)
    if is_none_or_empty(logfile):
        handler = logging.StreamHandler()
    else:
        handler = logging.FileHandler(logfile, encoding='utf-8')
    logging.getLogger().addHandler(handler)
    formatter = logging.Formatter('%(asctime)s %(levelname)s - %(message)s')
    formatter.default_msec_format = '%s.%03d'
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    _REGISTERED_LOGGER_HANDLERS.append(handler)


def set_verbose_logger_handlers():  # noqa
    # type: (None) -> None
    """Set logger handler formatters to more detail"""
    global _REGISTERED_LOGGER_HANDLERS
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s %(name)s:%(funcName)s:%(lineno)d '
        '%(message)s')
    formatter.default_msec_format = '%s.%03d'
    for handler in _REGISTERED_LOGGER_HANDLERS:
        handler.setFormatter(formatter)


def is_none_or_empty(obj):
    # type: (any) -> bool
    """Determine if object is None or empty
    :type any obj: object
    :rtype: bool
    :return: if object is None or empty
    """
    return obj is None or len(obj) == 0


def is_not_empty(obj):
    # type: (any) -> bool
    """Determine if object is not None and is length is > 0
    :type any obj: object
    :rtype: bool
    :return: if object is not None and length is > 0
    """
    return obj is not None and len(obj) > 0


def join_thread(thr):
    # type: (threading.Thread) -> None
    """Join a thread
    :type threading.Thread thr: thread to join
    """
    if on_python2():
        while True:
            thr.join(timeout=1)
            if not thr.isAlive():
                break
    else:
        thr.join()


def merge_dict(dict1, dict2):
    # type: (dict, dict) -> dict
    """Recursively merge dictionaries: dict2 on to dict1. This differs
    from dict.update() in that values that are dicts are recursively merged.
    Note that only dict value types are merged, not lists, etc.

    :param dict dict1: dictionary to merge to
    :param dict dict2: dictionary to merge with
    :rtype: dict
    :return: merged dictionary
    """
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        raise ValueError('dict1 or dict2 is not a dictionary')
    result = copy.deepcopy(dict1)
    for k, v in dict2.items():
        if k in result and isinstance(result[k], dict):
            result[k] = merge_dict(result[k], v)
        else:
            result[k] = copy.deepcopy(v)
    return result


def datetime_now():
    # type: (None) -> datetime.datetime
    """Return a timezone-aware datetime instance with local offset
    :rtype: datetime.datetime
    :return: datetime now with local tz
    """
    return datetime.datetime.now(tz=dateutil.tz.tzlocal())


def datetime_from_timestamp(ts, tz=None, as_utc=False):
    # type: (float, dateutil.tz, bool) -> datetime.datetime
    """Convert a timestamp into datetime with offset
    :param float ts: timestamp
    :param dateutil.tz tz: time zone or local tz if not specified
    :param bool as_utc: convert datetime to UTC
    :rtype: datetime.datetime
    :return: converted timestamp to datetime
    """
    if tz is None:
        tz = dateutil.tz.tzlocal()
    dt = datetime.datetime.fromtimestamp(ts, tz=tz)
    if as_utc:
        return dt.astimezone(tz=dateutil.tz.tzutc())
    else:
        return dt


def scantree(path):
    # type: (str) -> os.DirEntry
    """Recursively scan a directory tree
    :param str path: path to scan
    :rtype: DirEntry
    :return: DirEntry via generator
    """
    for entry in scandir(path):
        if entry.is_dir(follow_symlinks=True):
            # due to python2 compat, cannot use yield from here
            for t in scantree(entry.path):
                yield t
        else:
            yield entry


def get_mime_type(filename):
    # type: (str) -> str
    """Guess the type of a file based on its filename
    :param str filename: filename to guess the content-type
    :rtype: str
    :rturn: string of form 'class/type' for MIME content-type header
    """
    return (mimetypes.guess_type(filename)[0] or 'application/octet-stream')


def base64_encode_as_string(obj):  # noqa
    # type: (any) -> str
    """Encode object to base64
    :param any obj: object to encode
    :rtype: str
    :return: base64 encoded string
    """
    if on_python2():
        return base64.b64encode(obj)
    else:
        return str(base64.b64encode(obj), 'ascii')


def base64_decode_string(string):
    # type: (str) -> str
    """Base64 decode a string
    :param str string: string to decode
    :rtype: str
    :return: decoded string
    """
    return base64.b64decode(string)


def new_md5_hasher():
    # type: (None) -> md5.MD5
    """Create a new MD5 hasher
    :rtype: md5.MD5
    :return: new MD5 hasher
    """
    return hashlib.md5()


def page_align_content_length(length):
    # type: (int) -> int
    """Compute page boundary alignment
    :param int length: content length
    :rtype: int
    :return: aligned byte boundary
    """
    mod = length % _PAGEBLOB_BOUNDARY
    if mod != 0:
        return length + (_PAGEBLOB_BOUNDARY - mod)
    return length


def normalize_azure_path(path):
    # type: (str) -> str
    """Normalize remote path (strip slashes and use forward slashes)
    :param str path: path to normalize
    :rtype: str
    :return: normalized path
    """
    if is_none_or_empty(path):
        raise ValueError('provided path is invalid')
    _path = path.strip('/').strip('\\')
    return '/'.join(re.split('/|\\\\', _path))


def explode_azure_path(path):
    # type: (str) -> Tuple[str, str]
    """Explodes an azure path into a container or fileshare and the
    remaining virtual path
    :param str path: path to explode
    :rtype: tuple
    :return: container, vpath
    """
    rpath = normalize_azure_path(path).split('/')
    container = str(rpath[0])
    if len(rpath) > 1:
        rpath = '/'.join(rpath[1:])
    else:
        rpath = ''
    return container, rpath


def blob_is_snapshot(url):
    # type: (str) -> bool
    """Checks if the blob is a snapshot blob
    :param url str: blob url
    :rtype: bool
    :return: if blob is a snapshot blob
    """
    if '?snapshot=' in url:
        try:
            dateutil.parser.parse(url.split('?snapshot=')[-1])
            return True
        except (ValueError, OverflowError):
            pass
    return False


def parse_blob_snapshot_parameter(url):
    # type: (str) -> str
    """Retrieves the blob snapshot parameter from a url
    :param url str: blob url
    :rtype: str
    :return: snapshot parameter
    """
    if blob_is_snapshot(url):
        tmp = url.split('?snapshot=')
        if len(tmp) == 2:
            return tmp[0], tmp[1]
    return None


def parse_fileshare_or_file_snapshot_parameter(url):
    # type: (str) -> Tuple[str, str]
    """Checks if the fileshare or file is a snapshot
    :param url str: file url
    :rtype: tuple
    :return: (url, snapshot)
    """
    if is_not_empty(url):
        if '?sharesnapshot=' in url:
            try:
                tmp = url.split('?sharesnapshot=')
                if len(tmp) == 2:
                    dateutil.parser.parse(tmp[1])
                    return tmp[0], tmp[1]
            except (ValueError, OverflowError):
                pass
        elif '?snapshot=' in url:
            try:
                tmp = url.split('?snapshot=')
                if len(tmp) == 2:
                    dateutil.parser.parse(tmp[1])
                    return tmp[0], tmp[1]
            except (ValueError, OverflowError):
                pass
    return url, None
