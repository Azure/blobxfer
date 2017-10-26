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
import blobxfer.retry
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


def create_client(storage_account, timeout, proxy):
    # type: (blobxfer.operations.azure.StorageAccount,
    #        blobxfer.models.options.Timeout,
    #        blobxfer.models.options.HttpProxy) -> FileService
    """Create file client
    :param blobxfer.operations.azure.StorageAccount storage_account:
        storage account
    :param blobxfer.models.options.Timeout timeout: timeout
    :param blobxfer.models.options.HttpProxy proxy: proxy
    :rtype: FileService
    :return: file service client
    """
    if storage_account.is_sas:
        client = azure.storage.file.FileService(
            account_name=storage_account.name,
            sas_token=storage_account.key,
            endpoint_suffix=storage_account.endpoint,
            request_session=storage_account.session,
            socket_timeout=timeout.timeout)
    else:
        client = azure.storage.file.FileService(
            account_name=storage_account.name,
            account_key=storage_account.key,
            endpoint_suffix=storage_account.endpoint,
            request_session=storage_account.session,
            socket_timeout=timeout.timeout)
    # set proxy
    if proxy is not None:
        client.set_proxy(
            proxy.host, proxy.port, proxy.username, proxy.password)
    # set retry policy
    client.retry = blobxfer.retry.ExponentialRetryWithMaxWait(
        max_retries=timeout.max_retries).retry
    return client


def parse_file_path(filepath):
    # type: (pathlib.Path) -> Tuple[str, str, str]
    """Parse file path from file path
    :param str filepath: file path
    :rtype: tuple
    :return: (dirname, rest of path, snapshot)
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
    fname, snapshot = blobxfer.util.parse_fileshare_or_file_snapshot_parameter(
        fname)
    return (dirname, fname, snapshot)


def get_file_properties(
        client, fileshare, prefix, timeout=None, snapshot=None):
    # type: (azure.storage.file.FileService, str, str, int, str) ->
    #        azure.storage.file.models.File
    """Get file properties
    :param FileService client: blob client
    :param str fileshare: file share name
    :param str prefix: path prefix
    :param int timeout: timeout
    :param str snapshot: snapshot
    :rtype: azure.storage.file.models.File
    :return: file properties
    """
    dirname, fname, ss = parse_file_path(prefix)
    if ss is not None:
        if snapshot is not None:
            raise RuntimeError(
                'snapshot specified as {} but parsed {} from prefix {}'.format(
                    snapshot, ss, prefix))
        else:
            snapshot = ss
    try:
        return client.get_file_properties(
            share_name=fileshare,
            directory_name=dirname,
            file_name=fname,
            timeout=timeout,
            snapshot=snapshot,
        )
    except azure.common.AzureMissingResourceHttpError:
        return None


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
    if blobxfer.util.is_none_or_empty(prefix):
        return (False, None)
    file = get_file_properties(client, fileshare, prefix, timeout)
    if file is None:
        return (False, file)
    else:
        return (True, file)


def list_files(
        client, fileshare, prefix, recursive, timeout=None, snapshot=None):
    # type: (azure.storage.file.FileService, str, str, bool, int, str) ->
    #        azure.storage.file.models.File
    """List files in path
    :param azure.storage.file.FileService client: file client
    :param str fileshare: file share
    :param str prefix: path prefix
    :param bool recursive: recursive
    :param int timeout: timeout
    :param str snapshot: snapshot
    :rtype: azure.storage.file.models.File
    :return: generator of files
    """
    # if single file, then yield file and return
    _check = check_if_single_file(client, fileshare, prefix, timeout)
    if _check[0]:
        yield _check[1]
        return
    # get snapshot from fileshare
    if snapshot is None:
        fileshare, snapshot = \
            blobxfer.util.parse_fileshare_or_file_snapshot_parameter(fileshare)
        # get snapshot from prefix
        if snapshot is None:
            prefix, snapshot = \
                blobxfer.util.parse_fileshare_or_file_snapshot_parameter(
                    prefix)
    # else recursively list from prefix path
    dirs = [prefix]
    while len(dirs) > 0:
        dir = dirs.pop()
        files = client.list_directories_and_files(
            share_name=fileshare,
            directory_name=dir,
            timeout=timeout,
            snapshot=snapshot,
        )
        for file in files:
            fspath = str(
                pathlib.Path(dir if dir is not None else '') / file.name)
            if type(file) == azure.storage.file.models.File:
                fsprop = client.get_file_properties(
                    share_name=fileshare,
                    directory_name=None,
                    file_name=fspath,
                    timeout=timeout,
                    snapshot=snapshot,
                )
                yield fsprop
            else:
                if recursive:
                    dirs.append(fspath)


def list_all_files(client, fileshare, timeout=None):
    # type: (azure.storage.file.FileService, str, int) -> str
    """List all files in share
    :param azure.storage.file.FileService client: file client
    :param str fileshare: file share
    :param int timeout: timeout
    :rtype: str
    :return: file name
    """
    dirs = [None]
    while len(dirs) > 0:
        dir = dirs.pop()
        files = client.list_directories_and_files(
            share_name=fileshare,
            directory_name=dir,
            timeout=timeout,
        )
        for file in files:
            fspath = str(
                pathlib.Path(dir if dir is not None else '') / file.name)
            if type(file) == azure.storage.file.models.File:
                yield fspath
            else:
                dirs.append(fspath)


def delete_file(client, fileshare, name, timeout=None):
    # type: (azure.storage.file.FileService, str, str, int) -> None
    """Delete file from share
    :param azure.storage.file.FileService client: file client
    :param str fileshare: file share
    :param str name: file name
    :param int timeout: timeout
    """
    dir, fpath, snapshot = parse_file_path(name)
    if blobxfer.util.is_not_empty(snapshot):
        raise RuntimeError(
            'attempting to delete single file snapshot: {}/{}'.format(
                fileshare, name))
    client.delete_file(
        share_name=fileshare,
        directory_name=dir,
        file_name=fpath,
        timeout=timeout,
    )


def get_file_range(ase, offsets, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity,
    #        blobxfer.models.download.Offsets, int) -> bytes
    """Retrieve file range
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param blobxfer.models.download.Offsets offsets: download offsets
    :param int timeout: timeout
    :rtype: bytes
    :return: content for file range
    """
    dir, fpath, _ = parse_file_path(ase.name)
    return ase.client._get_file(
        share_name=ase.container,
        directory_name=dir,
        file_name=fpath,
        start_range=offsets.range_start,
        end_range=offsets.range_end,
        validate_content=False,  # HTTPS takes care of integrity during xfer
        timeout=timeout,
        snapshot=ase.snapshot,
    ).content


def create_share(ase, containers_created, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, dict, int) -> None
    """Create file share
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param dict containers_created: containers already created map
    :param int timeout: timeout
    """
    # check if auth allows create container
    if not ase.create_containers:
        return
    key = ase.client.account_name + ':file=' + ase.container
    if key in containers_created:
        return
    if ase.client.create_share(
            share_name=ase.container,
            fail_on_exist=False,
            timeout=timeout):
        logger.info('created file share {} on storage account {}'.format(
            ase.container, ase.client.account_name))
    # always add to set (as it could be pre-existing)
    containers_created.add(key)


def create_all_parent_directories(ase, dirs_created, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, dict, int) -> None
    """Create all parent directories for a file
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param dict dirs_created: directories already created map
    :param int timeout: timeout
    """
    dirs = pathlib.Path(ase.name).parts
    if len(dirs) <= 1:
        return
    # remove last part (which is the file)
    dirs = dirs[:-1]
    dk = ase.client.account_name + ':' + ase.container
    for i in range(0, len(dirs)):
        dir = str(pathlib.Path(*(dirs[0:i + 1])))
        if dk not in dirs_created or dir not in dirs_created[dk]:
            ase.client.create_directory(
                share_name=ase.container,
                directory_name=dir,
                fail_on_exist=False,
                timeout=timeout)
            if dk not in dirs_created:
                dirs_created[dk] = set()
            dirs_created[dk].add(dir)


def create_file(ase, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, int) -> None
    """Create file remotely
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param int timeout: timeout
    """
    dir, fpath, _ = parse_file_path(ase.name)
    ase.client.create_file(
        share_name=ase.container,
        directory_name=dir,
        file_name=fpath,
        content_length=ase.size,
        content_settings=azure.storage.file.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(fpath)
        ),
        timeout=timeout)


def put_file_range(ase, offsets, data, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity,
    #        blobxfer.models.upload.Offsets, bytes, int) -> None
    """Puts a range of bytes into the remote file
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param blobxfer.models.upload.Offsets offsets: upload offsets
    :param bytes data: data
    :param int timeout: timeout
    """
    dir, fpath, _ = parse_file_path(ase.name)
    ase.client.update_range(
        share_name=ase.container,
        directory_name=dir,
        file_name=fpath,
        data=data,
        start_range=offsets.range_start,
        end_range=offsets.range_end,
        validate_content=False,  # integrity is enforced with HTTPS
        timeout=timeout)


def set_file_md5(ase, md5, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, str, int) -> None
    """Set file properties MD5
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param str md5: md5 as base64
    :param int timeout: timeout
    """
    dir, fpath, _ = parse_file_path(ase.name)
    ase.client.set_file_properties(
        share_name=ase.container,
        directory_name=dir,
        file_name=fpath,
        content_settings=azure.storage.file.models.ContentSettings(
            content_type=blobxfer.util.get_mime_type(fpath),
            content_md5=md5,
        ),
        timeout=timeout)


def set_file_metadata(ase, metadata, timeout=None):
    # type: (blobxfer.models.azure.StorageEntity, dict, int) -> None
    """Set file metadata
    :param blobxfer.models.azure.StorageEntity ase: Azure StorageEntity
    :param dict metadata: metadata kv pairs
    :param int timeout: timeout
    """
    dir, fpath, _ = parse_file_path(ase.name)
    ase.client.set_file_metadata(
        share_name=ase.container,
        directory_name=dir,
        file_name=fpath,
        metadata=metadata,
        timeout=timeout)
