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
try:
    import queue
except ImportError:  # noqa
    import Queue as queue
# non-stdlib imports
import azure.storage.blob
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.download as models
import blobxfer.models.options as options
import blobxfer.operations.azure as azops
import blobxfer.util as util
# module under test
import blobxfer.operations.download as ops


@mock.patch('blobxfer.operations.azure.file.check_if_single_file')
@mock.patch('blobxfer.operations.azure.blob.check_if_single_blob')
def test_ensure_local_destination(patched_blob, patched_file, tmpdir):
    downdir = tmpdir.join('down')

    # non-file tests
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=mock.MagicMock(),
        local_destination_path=models.LocalDestinationPath(
            str(downdir)
        ),
    )

    with pytest.raises(RuntimeError):
        ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)

    asp = azops.SourcePath()
    p = 'cont/remote/path'
    asp.add_path_with_storage_account(p, 'sa')

    ds.add_azure_source_path(asp)

    patched_blob.return_value = False
    ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)
    assert ds.destination.is_dir

    patched_blob.return_value = True
    with pytest.raises(RuntimeError):
        ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)

    # file tests
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.File,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=mock.MagicMock(),
        local_destination_path=models.LocalDestinationPath(
            str(downdir)
        ),
    )

    ds.add_azure_source_path(asp)

    patched_file.return_value = (False, None)
    ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)
    assert ds.destination.is_dir

    patched_file.return_value = (True, mock.MagicMock())
    with pytest.raises(RuntimeError):
        ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)


def test_check_download_conditions(tmpdir):
    ap = tmpdir.join('a')
    ap.write('abc')
    ep = pathlib.Path(str(ap))
    nep = pathlib.Path(str(tmpdir.join('nep')))

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=False,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=options.SkipOn(
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

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=True,
            md5_match=True,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == ops.DownloadAction.CheckMd5

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=False,
            lmt_ge=False,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    result = d._check_download_conditions(ep, mock.MagicMock())
    assert result == ops.DownloadAction.Download

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=False,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = azmodels.StorageEntity('cont')
    rfile._size = util.page_align_content_length(ep.stat().st_size)
    rfile._mode = azmodels.StorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Skip

    rfile._size = ep.stat().st_size
    rfile._mode = azmodels.StorageModes.Page
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.Download

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=False,
            lmt_ge=True,
            md5_match=False,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), ds)
    rfile = azmodels.StorageEntity('cont')
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

    rfile = azmodels.StorageEntity('cont')
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


def test_post_md5_skip_on_check(tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._download_total = 0
    d._download_bytes_total = 0
    d._md5_offload = mock.MagicMock()

    lp = tmpdir.join('lpath').ensure(file=True)
    lpath = str(lp)
    rfile = azmodels.StorageEntity('cont')
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
    d._all_remote_files_processed = False
    d._download_terminate = True
    d._check_for_downloads_from_md5()
    assert d._add_to_download_queue.call_count == 0

    with mock.patch(
            'blobxfer.operations.download.Downloader.'
            'termination_check_md5',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._md5_map[lpath] = mock.MagicMock()
        d._download_set.add(pathlib.Path(lpath))
        d._md5_offload = mock.MagicMock()
        d._md5_offload.done_cv = multiprocessing.Condition()
        d._md5_offload.pop_done_queue.side_effect = [None, (lpath, False)]
        d._add_to_download_queue = mock.MagicMock()
        patched_tc.side_effect = [False, False, True]
        d._check_for_downloads_from_md5()
        assert d._add_to_download_queue.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.'
            'termination_check_md5',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._md5_map[lpath] = mock.MagicMock()
        d._download_set.add(pathlib.Path(lpath))
        d._md5_offload = mock.MagicMock()
        d._md5_offload.done_cv = multiprocessing.Condition()
        d._md5_offload.pop_done_queue.side_effect = [None]
        d._add_to_download_queue = mock.MagicMock()
        patched_tc.side_effect = [False, True, True]
        d._check_for_downloads_from_md5()
        assert d._add_to_download_queue.call_count == 0


def test_check_for_crypto_done():
    lpath = 'lpath'
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._download_set.add(pathlib.Path(lpath))
    dd = mock.MagicMock()
    d._dd_map[lpath] = dd
    d._crypto_offload = mock.MagicMock()
    d._crypto_offload.done_cv = multiprocessing.Condition()
    d._crypto_offload.pop_done_queue.side_effect = [
        None,
        lpath,
    ]
    d._all_remote_files_processed = False
    d._download_terminate = True
    d._check_for_crypto_done()
    assert dd.perform_chunked_integrity_check.call_count == 0

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._download_set.add(pathlib.Path(lpath))
        dd = mock.MagicMock()
        d._dd_map[lpath] = dd
        d._crypto_offload = mock.MagicMock()
        d._crypto_offload.done_cv = multiprocessing.Condition()
        d._crypto_offload.pop_done_queue.side_effect = [
            None,
            lpath,
        ]
        patched_tc.side_effect = [False, False, True]
        d._complete_chunk_download = mock.MagicMock()
        d._check_for_crypto_done()
        assert dd.perform_chunked_integrity_check.call_count == 1


def test_add_to_download_queue(tmpdir):
    path = tmpdir.join('a')
    lpath = pathlib.Path(str(path))
    ase = azmodels.StorageEntity('cont')
    ase._size = 1
    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = b'abc'
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._spec.options.chunk_size_bytes = 1

    d._add_to_download_queue(lpath, ase)
    assert d._download_queue.qsize() == 1
    assert path in d._dd_map


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


@mock.patch('blobxfer.operations.crypto.aes_cbc_decrypt_data')
@mock.patch('blobxfer.operations.azure.file.get_file_range')
@mock.patch('blobxfer.operations.azure.blob.get_blob_range')
def test_worker_thread_download(
        patched_gbr, patched_gfr, patched_acdd, tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._complete_chunk_download = mock.MagicMock()
    d._download_terminate = True
    d._worker_thread_download()
    assert d._complete_chunk_download.call_count == 0

    d._download_terminate = False
    d._all_remote_files_processed = True
    d._worker_thread_download()
    assert d._complete_chunk_download.call_count == 0

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        with mock.patch(
                'blobxfer.models.download.Descriptor.'
                'all_operations_completed',
                new_callable=mock.PropertyMock) as patched_aoc:
            d = ops.Downloader(
                mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
            opts = mock.MagicMock()
            opts.check_file_md5 = False
            opts.chunk_size_bytes = 16
            ase = azmodels.StorageEntity('cont')
            ase._size = 16
            ase._encryption = mock.MagicMock()
            ase._encryption.symmetric_key = b'abc'
            lp = pathlib.Path(str(tmpdir.join('a')))
            dd = models.Descriptor(lp, ase, opts, None)
            dd.next_offsets = mock.MagicMock(
                side_effect=[(None, None), (None, None)])
            dd.finalize_file = mock.MagicMock()
            dd.perform_chunked_integrity_check = mock.MagicMock()
            patched_aoc.side_effect = [False, True]
            patched_tc.side_effect = [False, False, False, True]
            d._dd_map[str(lp)] = dd
            d._download_set.add(lp)
            d._download_queue = mock.MagicMock()
            d._download_queue.get.side_effect = [queue.Empty, dd, dd]
            d._worker_thread_download()
            assert str(lp) not in d._dd_map
            assert dd.finalize_file.call_count == 1
            assert d._download_sofar == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        opts = mock.MagicMock()
        opts.check_file_md5 = True
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.File
        ase._size = 16
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('b')))
        dd = models.Descriptor(lp, ase, opts, None)
        dd.finalize_file = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        d._dd_map[str(lp)] = mock.MagicMock()
        d._download_set.add(lp)
        d._download_queue = mock.MagicMock()
        d._download_queue.get.side_effect = [dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_download()
        assert dd.perform_chunked_integrity_check.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        opts = mock.MagicMock()
        opts.check_file_md5 = False
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.Auto
        ase._size = 32
        ase._encryption = mock.MagicMock()
        ase._encryption.symmetric_key = b'abc'
        ase._encryption.content_encryption_iv = b'0' * 16
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('c')))
        dd = models.Descriptor(lp, ase, opts, None)
        dd.finalize_file = mock.MagicMock()
        dd.write_unchecked_hmac_data = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        d._crypto_offload = mock.MagicMock()
        d._crypto_offload.add_decrypt_chunk = mock.MagicMock()
        d._dd_map[str(lp)] = dd
        d._download_set.add(lp)
        d._download_queue = mock.MagicMock()
        d._download_queue.get.side_effect = [dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_download()
        assert d._crypto_offload.add_decrypt_chunk.call_count == 1
        assert dd.write_unchecked_hmac_data.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.crypto_processes = 0
        opts = mock.MagicMock()
        opts.check_file_md5 = False
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.Auto
        ase._size = 32
        ase._encryption = mock.MagicMock()
        ase._encryption.symmetric_key = b'abc'
        ase._encryption.content_encryption_iv = b'0' * 16
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('d')))
        dd = models.Descriptor(lp, ase, opts, None)
        dd.next_offsets()
        dd.write_unchecked_hmac_data = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        patched_acdd.return_value = b'0' * 16
        d._dd_map[str(lp)] = mock.MagicMock()
        d._download_set.add(lp)
        d._download_queue = mock.MagicMock()
        d._download_queue.get.side_effect = [dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_download()
        assert patched_acdd.call_count == 1
        assert dd.write_unchecked_hmac_data.call_count == 1
        assert dd.perform_chunked_integrity_check.call_count == 1


def test_cleanup_temporary_files(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, None)
    dd._allocate_disk_space()
    dd.cleanup_all_temporary_files = mock.MagicMock()
    dd.cleanup_all_temporary_files.side_effect = Exception
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = pathlib.Path('abc')
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert dd.local_path.exists()

    lp = pathlib.Path(str(tmpdir.join('b')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, None)
    dd._allocate_disk_space()
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert not dd.local_path.exists()

    lp = pathlib.Path(str(tmpdir.join('c')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, None)
    dd._allocate_disk_space()
    dd.cleanup_all_temporary_files = mock.MagicMock()
    dd.cleanup_all_temporary_files.side_effect = Exception
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert dd.local_path.exists()


def test_catalog_local_files_for_deletion(tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._spec.options.delete_extraneous_destination = False

    d._catalog_local_files_for_deletion()
    assert len(d._delete_after) == 0

    a = tmpdir.join('a')
    a.write('abc')
    d._spec.destination.path = tmpdir
    d._spec.options.delete_extraneous_destination = True
    d._spec.destination.is_dir = True

    d._catalog_local_files_for_deletion()
    assert len(d._delete_after) == 1
    assert pathlib.Path(str(a)) in d._delete_after


def test_delete_extraneous_files(tmpdir):
    a = tmpdir.join('a')
    a.write('abc')
    fp = pathlib.Path(str(a))

    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._spec.options.delete_extraneous_destination = True
    d._spec.destination.is_dir = True
    d._delete_after.add(fp)

    d._delete_extraneous_files()
    assert not fp.exists()

    # following should not throw exception
    d._delete_extraneous_files()


@mock.patch('time.clock')
@mock.patch('blobxfer.operations.md5.LocalFileMd5Offload')
@mock.patch('blobxfer.operations.azure.blob.list_blobs')
@mock.patch(
    'blobxfer.operations.download.Downloader.ensure_local_destination',
    return_value=True
)
def test_start(patched_eld, patched_lb, patched_lfmo, patched_tc, tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._cleanup_temporary_files = mock.MagicMock()
    d._download_start = datetime.datetime.now(tz=dateutil.tz.tzlocal())
    d._initialize_download_threads = mock.MagicMock()
    patched_lfmo._check_thread = mock.MagicMock()
    d._general_options.concurrency.crypto_processes = 1
    d._general_options.concurrency.md5_processes = 1
    d._general_options.resume_file = None
    d._spec.sources = []
    d._spec.options = mock.MagicMock()
    d._spec.options.chunk_size_bytes = 1
    d._spec.options.mode = azmodels.StorageModes.Auto
    d._spec.options.overwrite = True
    d._spec.skip_on = mock.MagicMock()
    d._spec.skip_on.md5_match = False
    d._spec.skip_on.lmt_ge = False
    d._spec.skip_on.filesize_match = False
    d._spec.destination = mock.MagicMock()
    d._spec.destination.path = pathlib.Path(str(tmpdir))
    d._download_start_time = util.datetime_now()

    p = '/cont/remote/path'
    asp = azops.SourcePath()
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
    d._general_options.resume_file = None
    d._run = mock.MagicMock(side_effect=KeyboardInterrupt)
    d._wait_for_download_threads = mock.MagicMock()
    d._cleanup_temporary_files = mock.MagicMock()
    d._md5_offload = mock.MagicMock()

    with pytest.raises(KeyboardInterrupt):
        d.start()
    assert d._wait_for_download_threads.call_count == 1
    assert d._cleanup_temporary_files.call_count == 1
