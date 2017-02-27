# coding=utf-8
"""Tests for download operations"""

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
import blobxfer.download.operations as ops


def test_check_download_conditions(tmpdir):
    ap = tmpdir.join('a')
    ap.write('abc')
    ep = pathlib.Path(str(ap))
    nep = pathlib.Path(str(tmpdir.join('nep')))

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(nep, mock.MagicMock())
    assert result == ops.DownloadAction.Download
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == ops.DownloadAction.Skip

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == ops.DownloadAction.CheckMd5

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == ops.DownloadAction.Download

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = models.AzureStorageEntity('cont')
    rfile._size = util.page_align_content_length(ep.stat().st_size)
    rfile._mode = models.AzureStorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Skip

    rfile._size = ep.stat().st_size
    rfile._mode = models.AzureStorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Download

    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = models.AzureStorageEntity('cont')
    rfile._lmt = datetime.datetime.now(dateutil.tz.tzutc()) + \
        datetime.timedelta(days=1)
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Download

    rfile._lmt = datetime.datetime.now(dateutil.tz.tzutc()) - \
        datetime.timedelta(days=1)
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Skip


def test_pre_md5_skip_on_check():
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
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
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_offload = mock.MagicMock()

    lpath = 'lpath'
    rfile = models.AzureStorageEntity('cont')
    rfile._md5 = 'abc'
    d._pre_md5_skip_on_check(lpath, rfile)
    d._download_set.add(pathlib.Path(lpath))
    assert lpath in d._md5_map

    d._post_md5_skip_on_check(lpath, True)
    assert lpath not in d._md5_map

    d._add_to_download_queue = mock.MagicMock()
    d._pre_md5_skip_on_check(lpath, rfile)
    d._download_set.add(pathlib.Path(lpath))
    d._post_md5_skip_on_check(lpath, False)
    assert d._add_to_download_queue.call_count == 1


def test_check_for_downloads_from_md5():
    lpath = 'lpath'
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_map[lpath] = mock.MagicMock()
    d._download_set.add(pathlib.Path(lpath))
    d._md5_offload = mock.MagicMock()
    d._md5_offload.done_cv = multiprocessing.Condition()
    d._md5_offload.pop_done_queue.side_effect = [None, (lpath, False)]
    d._add_to_download_queue = mock.MagicMock()

    with pytest.raises(StopIteration):
        d._check_for_downloads_from_md5()
    assert d._add_to_download_queue.call_count == 1

    d._add_to_download_queue = mock.MagicMock()
    d._all_remote_files_processed = False
    d._download_terminate = True
    d._check_for_downloads_from_md5()
    assert d._add_to_download_queue.call_count == 0


def test_initialize_and_terminate_download_threads():
    opts = mock.MagicMock()
    opts.concurrency.transfer_threads = 2
    d = ops.Downloader(opts, mock.MagicMock(), mock.MagicMock())
    d._worker_thread_download = mock.MagicMock()

    d._initialize_download_threads()
    assert len(d._download_threads) == 2

    d._wait_for_download_threads(terminate=True)
    assert d._download_terminate
    for thr in d._download_threads:
        assert not thr.is_alive()


@mock.patch('time.clock')
@mock.patch('blobxfer.md5.LocalFileMd5Offload')
@mock.patch('blobxfer.blob.operations.list_blobs')
@mock.patch('blobxfer.operations.ensure_local_destination', return_value=True)
def test_start(patched_eld, patched_lb, patched_lfmo, patched_tc, tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._initialize_download_threads = mock.MagicMock()
    patched_lfmo._check_thread = mock.MagicMock()
    d._general_options.concurrency.crypto_processes = 0
    d._spec.sources = []
    d._spec.options = mock.MagicMock()
    d._spec.options.chunk_size_bytes = 1
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
    b.properties.content_length = 1
    patched_lb.side_effect = [[b]]

    d._pre_md5_skip_on_check = mock.MagicMock()

    d._check_download_conditions = mock.MagicMock()
    d._check_download_conditions.return_value = ops.DownloadAction.Skip
    patched_tc.side_effect = [1, 2]
    d.start()
    assert d._pre_md5_skip_on_check.call_count == 0

    patched_lb.side_effect = [[b]]
    d._all_remote_files_processed = False
    d._check_download_conditions.return_value = ops.DownloadAction.CheckMd5
    patched_tc.side_effect = [1, 2]
    with pytest.raises(RuntimeError):
        d.start()
    assert d._pre_md5_skip_on_check.call_count == 1

    b.properties.content_length = 0
    patched_lb.side_effect = [[b]]
    d._all_remote_files_processed = False
    d._check_download_conditions.return_value = ops.DownloadAction.Download
    patched_tc.side_effect = [1, 2]
    with pytest.raises(RuntimeError):
        d.start()
    assert d._download_queue.qsize() == 1


def test_start_keyboard_interrupt():
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._run = mock.MagicMock(side_effect=KeyboardInterrupt)
    d._wait_for_download_threads = mock.MagicMock()
    d._md5_offload = mock.MagicMock()

    with pytest.raises(KeyboardInterrupt):
        d.start()
    assert d._wait_for_download_threads.call_count == 1
