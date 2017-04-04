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
import logging
# non-stdlib imports
# local imports
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


def compute_md5_for_file_asbase64(filename, pagealign=False, blocksize=65536):
    # type: (str, bool, int) -> str
    """Compute MD5 hash for file and encode as Base64
    :param str filename: file to compute MD5 for
    :param bool pagealign: page align data
    :param int blocksize: block size
    :rtype: str
    :return: MD5 for file encoded as Base64
    """
    hasher = blobxfer.util.new_md5_hasher()
    with open(filename, 'rb') as filedesc:
        while True:
            buf = filedesc.read(blocksize)
            if not buf:
                break
            buflen = len(buf)
            if pagealign and buflen < blocksize:
                aligned = blobxfer.util.page_align_content_length(buflen)
                if aligned != buflen:
                    buf = buf.ljust(aligned, b'\0')
            hasher.update(buf)
        return blobxfer.util.base64_encode_as_string(hasher.digest())


def compute_md5_for_data_asbase64(data):
    # type: (obj) -> str
    """Compute MD5 hash for bits and encode as Base64
    :param any data: data to compute MD5 for
    :rtype: str
    :return: MD5 for data
    """
    hasher = blobxfer.util.new_md5_hasher()
    hasher.update(data)
    return blobxfer.util.base64_encode_as_string(hasher.digest())
