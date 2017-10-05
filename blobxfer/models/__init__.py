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
import fnmatch
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# local imports


class _BaseSourcePaths(object):
    """Base Source Paths"""
    def __init__(self):
        # type: (_BaseSourcePaths) -> None
        """Ctor for _BaseSourcePaths
        :param _BaseSourcePaths self: this
        """
        self._include = None
        self._exclude = None
        self._paths = []

    @property
    def paths(self):
        # type: (_BaseSourcePaths) -> List[pathlib.Path]
        """Stored paths
        :param _BaseSourcePaths self: this
        :rtype: list
        :return: list of pathlib.Path
        """
        return self._paths

    def add_includes(self, includes):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of includes
        :param _BaseSourcePaths self: this
        :param list includes: list of includes
        """
        if not isinstance(includes, list):
            if isinstance(includes, tuple):
                includes = list(includes)
            else:
                includes = [includes]
        # remove any starting rglob spec
        incl = []
        for inc in includes:
            tmp = pathlib.Path(inc).parts
            if tmp[0] == '**':
                if len(tmp) == 1:
                    continue
                else:
                    incl.append(str(pathlib.Path(*tmp[1:])))
            else:
                incl.append(inc)
        # check for any remaining rglob specs
        if any(['**' in x for x in incl]):
            raise ValueError('invalid include specification containing "**"')
        if self._include is None:
            self._include = incl
        else:
            self._include.extend(incl)

    def add_excludes(self, excludes):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of excludes
        :param _BaseSourcePaths self: this
        :param list excludes: list of excludes
        """
        if not isinstance(excludes, list):
            if isinstance(excludes, tuple):
                excludes = list(excludes)
            else:
                excludes = [excludes]
        # remove any starting rglob spec
        excl = []
        for exc in excludes:
            tmp = pathlib.Path(exc).parts
            if tmp[0] == '**':
                if len(tmp) == 1:
                    continue
                else:
                    excl.append(str(pathlib.Path(*tmp[1:])))
            else:
                excl.append(exc)
        # check for any remaining rglob specs
        if any(['**' in x for x in excl]):
            raise ValueError('invalid exclude specification containing "**"')
        if self._exclude is None:
            self._exclude = excl
        else:
            self._exclude.extend(excl)

    def add_path(self, path):
        # type: (_BaseSourcePaths, str) -> None
        """Add a local path
        :param _BaseSourcePaths self: this
        :param str path: path to add
        """
        if isinstance(path, pathlib.Path):
            self._paths.append(path)
        else:
            self._paths.append(pathlib.Path(path))

    def add_paths(self, paths):
        # type: (_BaseSourcePaths, list) -> None
        """Add a list of local paths
        :param _BaseSourcePaths self: this
        :param list paths: paths to add
        """
        for path in paths:
            self.add_path(path)

    def _inclusion_check(self, path):
        # type: (_BaseSourcePaths, pathlib.Path) -> bool
        """Check file for inclusion against filters
        :param _BaseSourcePaths self: this
        :param pathlib.Path path: path to check
        :rtype: bool
        :return: if file should be included
        """
        _spath = str(path)
        inc = True
        if self._include is not None:
            inc = any([fnmatch.fnmatch(_spath, x) for x in self._include])
        if inc and self._exclude is not None:
            inc = not any([fnmatch.fnmatch(_spath, x) for x in self._exclude])
        return inc
