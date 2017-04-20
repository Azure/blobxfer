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
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# local imports
import blobxfer.models
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


LocalPath = collections.namedtuple(
    'LocalPath', [
        'parent_path',
        'relative_path',
    ]
)


class LocalSourcePath(blobxfer.models._BaseSourcePaths):
    """Local Source Path"""
    def files(self):
        # type: (LocalSourcePaths) -> LocalPath
        """Generator for files in paths
        :param LocalSourcePath self: this
        :rtype: LocalPath
        :return: LocalPath
        """
        for _path in self._paths:
            _ppath = os.path.expandvars(os.path.expanduser(str(_path)))
            _expath = pathlib.Path(_ppath)
            for entry in blobxfer.util.scantree(_ppath):
                _rpath = pathlib.Path(entry.path).relative_to(_ppath)
                if not self._inclusion_check(_rpath):
                    logger.debug(
                        'skipping file {} due to filters'.format(_rpath))
                    continue
                yield LocalPath(parent_path=_expath, relative_path=_rpath)


class Specification(object):
    """Upload Specification"""
    def __init__(
            self, upload_options, skip_on_options, remote_destination_path):
        # type: (Specification, blobxfer.models.options.Upload,
        #        blobxfer.models.options.SkipOn, RemoteDestinationPath) -> None
        """Ctor for Specification
        :param UploadSpecification self: this
        :param blobxfer.models.options.Upload upload_options: upload options
        :param blobxfer.models.options.SkipOn skip_on_options: skip on options
        :param RemoteDestinationPath remote_destination_path: remote dest path
        """
        self.options = upload_options
        self.skip_on = skip_on_options
        self.destination = remote_destination_path
        self.sources = []

    def add_local_source_path(self, source):
        # type: (Specification, LocalSourcePath) -> None
        """Add a Local Source Path
        :param UploadSpecification self: this
        :param LocalSourcePath source: Local source path to add
        """
        self.sources.append(source)
