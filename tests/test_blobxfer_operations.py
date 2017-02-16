# coding=utf-8
"""Tests for operations"""

# stdlib imports
from mock import (
    MagicMock,
    patch,
)
# non-stdlib imports
import pytest
# local imports
import blobxfer.models
# module under test
import blobxfer.operations as ops


@patch('blobxfer.file.operations.check_if_single_file')
@patch('blobxfer.blob.operations.check_if_single_blob')
def test_ensure_local_destination(patched_blob, patched_file, tmpdir):
    downdir = tmpdir.join('down')

    # non-file tests
    ds = blobxfer.models.DownloadSpecification(
        download_options=blobxfer.models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=blobxfer.models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=MagicMock(),
        local_destination_path=blobxfer.models.LocalDestinationPath(
            str(downdir)
        ),
    )

    with pytest.raises(RuntimeError):
        ops.ensure_local_destination(MagicMock(), ds)

    asp = blobxfer.models.AzureSourcePath()
    p = 'cont/remote/path'
    asp.add_path_with_storage_account(p, 'sa')

    ds.add_azure_source_path(asp)

    patched_blob.return_value = False
    ops.ensure_local_destination(MagicMock(), ds)
    assert ds.destination.is_dir

    patched_blob.return_value = True
    with pytest.raises(RuntimeError):
        ops.ensure_local_destination(MagicMock(), ds)

    # file tests
    ds = blobxfer.models.DownloadSpecification(
        download_options=blobxfer.models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=blobxfer.models.AzureStorageModes.File,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=MagicMock(),
        local_destination_path=blobxfer.models.LocalDestinationPath(
            str(downdir)
        ),
    )

    ds.add_azure_source_path(asp)

    patched_file.return_value = False
    ops.ensure_local_destination(MagicMock(), ds)
    assert ds.destination.is_dir

    patched_file.return_value = True
    with pytest.raises(RuntimeError):
        ops.ensure_local_destination(MagicMock(), ds)
