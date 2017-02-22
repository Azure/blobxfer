# coding=utf-8
"""Tests for download"""

# stdlib imports
import datetime
import dateutil.tz
import mock
import multiprocessing
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import azure.storage.blob
import pytest
# local imports
import blobxfer.models as models
import blobxfer.util as util
# module under test
import blobxfer.download as dl


def test_check_download_conditions(tmpdir):
    ap = tmpdir.join('a')
    ap.write('abc')
    ep = pathlib.Path(str(ap))
    nep = pathlib.Path(str(tmpdir.join('nep')))

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=False,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=True,
            lmt_ge=True,
            md5_match=True,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(nep, mock.MagicMock())
    assert result == dl.DownloadAction.Download
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == dl.DownloadAction.Skip

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=True,
            lmt_ge=True,
            md5_match=True,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == dl.DownloadAction.CheckMd5

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=False,
            lmt_ge=False,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == dl.DownloadAction.Download

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=True,
            lmt_ge=False,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = models.AzureStorageEntity('cont')
    rfile._size = util.page_align_content_length(ep.stat().st_size)
    rfile._mode = models.AzureStorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == dl.DownloadAction.Skip

    rfile._size = ep.stat().st_size
    rfile._mode = models.AzureStorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == dl.DownloadAction.Download

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=False,
            lmt_ge=True,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = models.AzureStorageEntity('cont')
    rfile._lmt = datetime.datetime.now(dateutil.tz.tzutc()) + \
        datetime.timedelta(days=1)
    result = d._check_download_conditions(ep, rfile)
    assert result == dl.DownloadAction.Download

    rfile._lmt = datetime.datetime.now(dateutil.tz.tzutc()) - \
        datetime.timedelta(days=1)
    result = d._check_download_conditions(ep, rfile)
    assert result == dl.DownloadAction.Skip


def test_pre_md5_skip_on_check():
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_offload = mock.MagicMock()

    rfile = models.AzureStorageEntity('cont')
    rfile._encryption = mock.MagicMock()
    rfile._encryption.blobxfer_extensions = mock.MagicMock()
    rfile._encryption.blobxfer_extensions.pre_encrypted_content_md5 = \
        'abc'

    lpath = 'lpath'
    d._pre_md5_skip_on_check(lpath, rfile)
    assert lpath in d._md5_map

    lpath = 'lpath2'
    rfile._encryption = None
    rfile._md5 = 'abc'
    d._pre_md5_skip_on_check(lpath, rfile)
    assert lpath in d._md5_map


def test_post_md5_skip_on_check():
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_offload = mock.MagicMock()

    lpath = 'lpath'
    rfile = models.AzureStorageEntity('cont')
    rfile._md5 = 'abc'
    d._pre_md5_skip_on_check(lpath, rfile)
    assert lpath in d._md5_map

    d._post_md5_skip_on_check(lpath, True)
    assert lpath not in d._md5_map

    # TODO test mismatch


def test_initialize_check_md5_downloads_thread():
    lpath = 'lpath'
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_map[lpath] = mock.MagicMock()
    d._md5_offload = mock.MagicMock()
    d._md5_offload.done_cv = multiprocessing.Condition()
    d._md5_offload.get_localfile_md5_done = mock.MagicMock()
    d._md5_offload.get_localfile_md5_done.side_effect = [None, (lpath, True)]
    d._post_md5_skip_on_check = mock.MagicMock()

    d._initialize_check_md5_downloads_thread()
    d._all_remote_files_processed = True
    d._md5_map.clear()
    d._md5_offload.done_cv.acquire()
    d._md5_offload.done_cv.notify()
    d._md5_offload.done_cv.release()
    d._md5_check_thread.join()

    assert d._post_md5_skip_on_check.call_count == 1


@mock.patch('blobxfer.md5.LocalFileMd5Offload')
@mock.patch('blobxfer.blob.operations.list_blobs')
@mock.patch('blobxfer.operations.ensure_local_destination', return_value=True)
def test_start(patched_eld, patched_lb, patched_lfmo, tmpdir):
    d = dl.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._initialize_check_md5_downloads_thread = mock.MagicMock()
    d._md5_check_thread = mock.MagicMock()
    d._spec.sources = []
    d._spec.options = mock.MagicMock()
    d._spec.options.mode = models.AzureStorageModes.Auto
    d._spec.options.overwrite = True
    d._spec.skip_on = mock.MagicMock()
    d._spec.skip_on.md5_match = False
    d._spec.skip_on.lmt_ge = False
    d._spec.skip_on.filesize_match = False
    d._spec.destination = mock.MagicMock()
    d._spec.destination.path = pathlib.Path(str(tmpdir))

    p = '/cont/remote/path'
    asp = models.AzureSourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    d._spec.sources.append(asp)

    b = azure.storage.blob.models.Blob(name='name')
    patched_lb.side_effect = [[b]]

    d._check_download_conditions = mock.MagicMock()
    d._check_download_conditions.return_value = dl.DownloadAction.Skip
    d.start()
    # TODO assert

    patched_lb.side_effect = [[b]]
    d._all_remote_files_processed = False
    d._check_download_conditions.return_value = dl.DownloadAction.CheckMd5
    d._pre_md5_skip_on_check = mock.MagicMock()
    d.start()
    assert d._pre_md5_skip_on_check.call_count == 1

    patched_lb.side_effect = [[b]]
    d._all_remote_files_processed = False
    d._check_download_conditions.return_value = dl.DownloadAction.Download
    d.start()
    # TODO assert
