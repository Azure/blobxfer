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
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import azure.common
import azure.storage.file
# local imports

# create logger
logger = logging.getLogger(__name__)


def create_client(storage_account):
    # type: (blobxfer.models.AzureStorageAccount) -> FileService
    """Create file client
    :param blobxfer.models.AzureStorageAccount storage_account: storage account
    :rtype: FileService
    :return: file service client
    """
    if storage_account.is_sas:
        client = azure.storage.file.FileService(
            account_name=storage_account.name,
            sas_token=storage_account.key,
            endpoint_suffix=storage_account.endpoint)
    else:
        client = azure.storage.file.FileService(
            account_name=storage_account.name,
            account_key=storage_account.key,
            endpoint_suffix=storage_account.endpoint)
    return client


def parse_file_path(filepath):
    # type: (pathlib.Path) -> Tuple[str, str]
    """Parse file path from file path
    :param str filepath: file path
    :rtype: tuple
    :return: (dirname, rest of path)
    """
    if not isinstance(filepath, pathlib.Path):
        filepath = pathlib.Path(filepath)
    dirname = '/'.join(filepath.parts[:len(filepath.parts) - 1])
    if len(dirname) == 0:
        dirname = None
    if len(filepath.parts) > 0:
        fname = filepath.parts[-1]
    else:
        fname = None
    return (dirname, fname)


def check_if_single_file(client, fileshare, prefix, timeout=None):
    # type: (azure.storage.file.FileService, str, str, int) ->
    #        Tuple[bool, azure.storage.file.models.File]
    """Check if prefix is a single file or multiple files
    :param FileService client: blob client
    :param str fileshare: file share name
    :param str prefix: path prefix
    :param int timeout: timeout
    :rtype: tuple
    :return: (if prefix in fileshare is a single file, file)
    """
    dirname, fname = parse_file_path(prefix)
    file = None
    try:
        file = client.get_file_properties(
            share_name=fileshare,
            directory_name=dirname,
            file_name=fname,
            timeout=timeout,
        )
    except azure.common.AzureMissingResourceHttpError:
        return (False, file)
    return (True, file)


def list_files(client, fileshare, prefix, timeout=None):
    # type: (azure.storage.file.FileService, str, str, int) ->
    #        azure.storage.file.models.File
    """List files in path
    :param azure.storage.file.FileService client: file client
    :param str fileshare: file share
    :param str prefix: path prefix
    :param int timeout: timeout
    :rtype: azure.storage.file.models.File
    :return: generator of files
    """
    # if single file, then yield file and return
    _check = check_if_single_file(client, fileshare, prefix, timeout)
    if _check[0]:
        yield _check[1]
        return
    # else recursively list from prefix path
    dirs = [prefix]
    while len(dirs) > 0:
        dir = dirs.pop()
        files = client.list_directories_and_files(
            share_name=fileshare,
            directory_name=dir,
            timeout=timeout,
        )
        for file in files:
            fspath = str(pathlib.Path(
                dir if dir is not None else '' / file.name))
            if isinstance(file, azure.storage.file.File):
                fsprop = client.get_file_properties(
                    share_name=fileshare,
                    directory_name=dir,
                    file_name=file.name,
                    timeout=timeout,
                )
                yield fsprop
            else:
                dirs.append(fspath)
