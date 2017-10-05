# coding=utf-8
"""Tests for download operations"""

# stdlib imports
import datetime
try:
    import unittest.mock as mock
except ImportError:  # noqa
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
import dateutil.tz
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
    downdir.mkdir()

    # no spec sources
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=False,
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

    # blob directory
    asp = azops.SourcePath()
    p = 'cont/remote/path'
    asp.add_path_with_storage_account(p, 'sa')
    ds.add_azure_source_path(asp)
    patched_blob.return_value = False
    ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)
    assert ds.destination.is_dir

    # blob single file + rename
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=mock.MagicMock(),
        local_destination_path=models.LocalDestinationPath(
            str(downdir)
        ),
    )
    ds.add_azure_source_path(asp)
    patched_blob.return_value = True
    with pytest.raises(RuntimeError):
        ops.Downloader.ensure_local_destination(mock.MagicMock(), ds)

    # file directory
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.File,
            overwrite=True,
            recursive=True,
            rename=False,
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

    # file single + rename
    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.File,
            overwrite=True,
            recursive=True,
            rename=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=mock.MagicMock(),
        local_destination_path=models.LocalDestinationPath(
            str(downdir)
        ),
    )
    ds.add_azure_source_path(asp)
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
            rename=False,
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
    rfile = mock.MagicMock()
    rfile.vectored_io = None
    result = d._check_download_conditions(nep, rfile)
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
            rename=False,
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
    rfile = mock.MagicMock()
    rfile.md5 = 'abc'
    rfile._encryption = None
    result = d._check_download_conditions(ep, rfile)
    assert result == ops.DownloadAction.CheckMd5

    ds = models.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=False,
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
            rename=False,
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
    rfile._encryption = None
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
            rename=False,
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
    rfile._encryption = None
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
    rfile._encryption.blobxfer_extensions.pre_encrypted_content_md5 = 'abc'
    rfile._client = mock.MagicMock()
    rfile._client.primary_endpoint = 'ep'
    rfile._name = 'name'
    rfile._size = 32
    rfile._vio = mock.MagicMock()
    rfile._vio.offset_start = 0
    rfile._vio.total_size = 32

    lpath = pathlib.Path('lpath')
    key = ops.Downloader.create_unique_transfer_operation_id(rfile)
    d._pre_md5_skip_on_check(lpath, rfile)
    assert key in d._md5_map

    rfile._name = 'name2'
    rfile._vio = None
    lpath = 'lpath2'
    rfile._encryption = None
    rfile._md5 = 'abc'
    key = ops.Downloader.create_unique_transfer_operation_id(rfile)
    d._pre_md5_skip_on_check(lpath, rfile)
    assert key in d._md5_map

    assert len(d._md5_map) == 2


def test_post_md5_skip_on_check(tmpdir):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._download_total = 0
    d._download_bytes_total = 0
    d._md5_offload = mock.MagicMock()

    lp = tmpdir.join('lpath').ensure(file=True)
    lpath = str(lp)
    rfile = azmodels.StorageEntity('cont')
    rfile._md5 = 'abc'
    rfile._client = mock.MagicMock()
    rfile._client.primary_endpoint = 'ep'
    rfile._name = 'name'
    rfile._vio = None
    rfile._size = 256
    d._pre_md5_skip_on_check(lpath, rfile)
    key = ops.Downloader.create_unique_transfer_operation_id(rfile)
    d._transfer_set.add(key)
    assert key in d._md5_map

    d._post_md5_skip_on_check(key, lpath, None, True)
    assert key not in d._md5_map

    d._add_to_download_queue = mock.MagicMock()
    d._pre_md5_skip_on_check(lpath, rfile)
    d._transfer_set.add(key)
    d._post_md5_skip_on_check(key, lpath, rfile._size, False)
    assert d._add_to_download_queue.call_count == 1


def test_check_for_downloads_from_md5():
    lpath = 'lpath'
    rfile = azmodels.StorageEntity('cont')
    rfile._md5 = 'abc'
    rfile._client = mock.MagicMock()
    rfile._client.primary_endpoint = 'ep'
    rfile._name = 'name'
    rfile._vio = None
    rfile._size = 256
    key = ops.Downloader.create_unique_transfer_operation_id(rfile)
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._md5_map[key] = rfile
    d._transfer_set.add(key)
    d._md5_offload = mock.MagicMock()
    d._md5_offload.done_cv = multiprocessing.Condition()
    d._md5_offload.pop_done_queue.side_effect = [
        None,
        (key, lpath, rfile._size, False),
    ]
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
        d._md5_map[key] = rfile
        d._transfer_set.add(key)
        d._md5_offload = mock.MagicMock()
        d._md5_offload.done_cv = multiprocessing.Condition()
        d._md5_offload.pop_done_queue.side_effect = [
            None,
            (key, lpath, rfile._size, False),
        ]
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
        d._md5_map[key] = rfile
        d._transfer_set.add(key)
        d._md5_offload = mock.MagicMock()
        d._md5_offload.done_cv = multiprocessing.Condition()
        d._md5_offload.pop_done_queue.side_effect = [None]
        d._add_to_download_queue = mock.MagicMock()
        patched_tc.side_effect = [False, True, True]
        d._check_for_downloads_from_md5()
        assert d._add_to_download_queue.call_count == 0


def test_check_for_crypto_done():
    lpath = 'lpath'
    rfile = azmodels.StorageEntity('cont')
    rfile._md5 = 'abc'
    rfile._client = mock.MagicMock()
    rfile._client.primary_endpoint = 'ep'
    rfile._name = 'name'
    rfile._vio = None
    rfile._size = 256
    key = ops.Downloader.create_unique_transfer_operation_id(rfile)
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._transfer_set.add(key)
    dd = mock.MagicMock()
    d._dd_map[lpath] = dd
    offsets = mock.MagicMock()
    offsets.range_start = 0
    d._crypto_offload = mock.MagicMock()
    d._crypto_offload.done_cv = multiprocessing.Condition()
    d._crypto_offload.pop_done_queue.side_effect = [
        None,
        (lpath, offsets)
    ]
    d._all_remote_files_processed = False
    d._download_terminate = True
    d._check_for_crypto_done()
    assert dd.perform_chunked_integrity_check.call_count == 0

    # check successful integrity check call
    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._transfer_set.add(key)
        dd = mock.MagicMock()
        dd.entity = rfile
        dd.final_path = lpath
        d._dd_map[lpath] = dd
        d._crypto_offload = mock.MagicMock()
        d._crypto_offload.done_cv = multiprocessing.Condition()
        d._crypto_offload.pop_done_queue.side_effect = [
            None,
            (lpath, offsets),
            None,
        ]
        patched_tc.side_effect = [False, False, False, True, True]
        d._complete_chunk_download = mock.MagicMock()
        d._check_for_crypto_done()
        assert dd.perform_chunked_integrity_check.call_count == 1

    # check KeyError on result
    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._transfer_set.add(key)
        dd = mock.MagicMock()
        dd.entity = rfile
        dd.final_path = lpath
        d._crypto_offload = mock.MagicMock()
        d._crypto_offload.done_cv = multiprocessing.Condition()
        d._crypto_offload.pop_done_queue.side_effect = [
            None,
            (lpath, offsets),
        ]
        patched_tc.side_effect = [False, False, True]
        d._complete_chunk_download = mock.MagicMock()
        d._check_for_crypto_done()
        assert dd.perform_chunked_integrity_check.call_count == 0


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
    assert d._transfer_queue.qsize() == 1
    assert path in d._dd_map


def test_initialize_and_terminate_threads():
    opts = mock.MagicMock()
    opts.concurrency.transfer_threads = 2
    opts.concurrency.disk_threads = 2
    d = ops.Downloader(opts, mock.MagicMock(), mock.MagicMock())
    d._worker_thread_transfer = mock.MagicMock()

    d._initialize_transfer_threads()
    assert len(d._transfer_threads) == 2

    d._wait_for_transfer_threads(terminate=True)
    assert d._download_terminate
    for thr in d._transfer_threads:
        assert not thr.is_alive()

    d._initialize_disk_threads()
    assert len(d._disk_threads) == 2

    d._wait_for_disk_threads(terminate=True)
    assert d._download_terminate
    for thr in d._disk_threads:
        assert not thr.is_alive()


def test_process_download_descriptor_vio(tmpdir):
    with mock.patch(
            'blobxfer.models.download.Descriptor.all_operations_completed',
            new_callable=mock.PropertyMock) as patched_aoc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.transfer_threads = 1
        d._general_options.concurrency.disk_threads = 1
        opts = mock.MagicMock()
        opts.check_file_md5 = True
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.File
        ase._size = 16
        ase._client = mock.MagicMock()
        ase._client.primary_endpoint = 'ep'
        ase._name = 'name'
        ase._vio = mock.MagicMock()
        ase._vio.total_slices = 2

        lp = pathlib.Path(str(tmpdir.join('b')))
        dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
        dd.next_offsets = mock.MagicMock()
        dd.next_offsets.return_value = (None, None)
        patched_aoc.return_value = True
        dd.finalize_file = mock.MagicMock()
        key = ops.Downloader.create_unique_transfer_operation_id(ase)
        d._transfer_set.add(key)
        d._dd_map[str(lp)] = mock.MagicMock()

        d._process_download_descriptor(dd)
        assert dd.finalize_file.call_count == 0

        d._transfer_set.add(key)
        d._dd_map[str(lp)] = mock.MagicMock()
        d._process_download_descriptor(dd)
        assert dd.finalize_file.call_count == 1


@mock.patch('blobxfer.operations.crypto.aes_cbc_decrypt_data')
@mock.patch('blobxfer.operations.azure.file.get_file_range')
@mock.patch('blobxfer.operations.azure.blob.get_blob_range')
def test_worker_thread_transfer(
        patched_gbr, patched_gfr, patched_acdd, tmpdir):
    # test disk set > max set length
    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._process_download_descriptor = mock.MagicMock()
        d._general_options.concurrency.disk_threads = 1
        d._disk_set.add(0)
        d._disk_set.add(1)
        d._disk_set.add(2)
        d._disk_set.add(3)
        d._disk_set.add(4)

        patched_tc.side_effect = [False, True]
        d._worker_thread_transfer()
        assert d._process_download_descriptor.call_count == 0

    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._process_download_descriptor = mock.MagicMock()
    d._download_terminate = True
    d._general_options.concurrency.transfer_threads = 1
    d._general_options.concurrency.disk_threads = 1
    d._worker_thread_transfer()
    assert d._process_download_descriptor.call_count == 0

    d._download_terminate = False
    d._all_remote_files_processed = True
    d._worker_thread_transfer()
    assert d._process_download_descriptor.call_count == 0

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        patched_tc.side_effect = [False, False, True]
        ase = azmodels.StorageEntity('cont')
        ase._size = 16
        ase._encryption = mock.MagicMock()
        ase._encryption.symmetric_key = b'abc'
        lp = pathlib.Path(str(tmpdir.join('exc')))
        opts = mock.MagicMock()
        opts.check_file_md5 = False
        opts.chunk_size_bytes = 16
        dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
        d._transfer_queue = mock.MagicMock()
        d._transfer_queue.get.side_effect = [queue.Empty, dd]
        d._process_download_descriptor = mock.MagicMock()
        d._process_download_descriptor.side_effect = RuntimeError('oops')
        d._worker_thread_transfer()
        assert len(d._exceptions) == 1
        assert d._process_download_descriptor.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        with mock.patch(
                'blobxfer.models.download.Descriptor.'
                'all_operations_completed',
                new_callable=mock.PropertyMock) as patched_aoc:
            d = ops.Downloader(
                mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
            d._general_options.concurrency.transfer_threads = 1
            d._general_options.concurrency.disk_threads = 1
            opts = mock.MagicMock()
            opts.check_file_md5 = False
            opts.chunk_size_bytes = 16
            ase = azmodels.StorageEntity('cont')
            ase._size = 16
            ase._client = mock.MagicMock()
            ase._client.primary_endpoint = 'ep'
            ase._name = 'name'
            ase._vio = None
            key = ops.Downloader.create_unique_transfer_operation_id(ase)
            ase._encryption = mock.MagicMock()
            ase._encryption.symmetric_key = b'abc'
            lp = pathlib.Path(str(tmpdir.join('a')))
            dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
            dd.next_offsets = mock.MagicMock(
                side_effect=[(None, 1), (None, 2)])
            dd.finalize_integrity = mock.MagicMock()
            dd.finalize_file = mock.MagicMock()
            dd.perform_chunked_integrity_check = mock.MagicMock()
            dd.all_operations_completed.side_effect = [False, True]
            patched_aoc.side_effect = [False, True]
            patched_tc.side_effect = [False, False, False, True]
            d._dd_map[str(lp)] = dd
            d._transfer_set.add(key)
            d._transfer_queue = mock.MagicMock()
            d._transfer_queue.get.side_effect = [queue.Empty, dd, dd]
            d._worker_thread_transfer()
            assert str(lp) not in d._dd_map
            assert dd.finalize_file.call_count == 1
            assert d._download_sofar == 1
            assert d._download_bytes_sofar == 3

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.transfer_threads = 1
        d._general_options.concurrency.disk_threads = 1
        opts = mock.MagicMock()
        opts.check_file_md5 = True
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.File
        ase._size = 16
        ase._client = mock.MagicMock()
        ase._client.primary_endpoint = 'ep'
        ase._name = 'name'
        ase._vio = None
        key = ops.Downloader.create_unique_transfer_operation_id(ase)
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('b')))
        dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
        dd.finalize_file = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        d._dd_map[str(lp)] = mock.MagicMock()
        d._transfer_set.add(key)
        d._transfer_queue = mock.MagicMock()
        d._transfer_queue.get.side_effect = [dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_transfer()
        assert len(d._disk_set) == 1
        a, b, c = d._disk_queue.get()
        d._process_data(a, b, c)
        assert dd.perform_chunked_integrity_check.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.transfer_threads = 1
        d._general_options.concurrency.disk_threads = 1
        opts = mock.MagicMock()
        opts.check_file_md5 = False
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.Auto
        ase._size = 32
        ase._encryption = mock.MagicMock()
        ase._encryption.symmetric_key = b'abc'
        ase._encryption.content_encryption_iv = b'0' * 16
        ase._client = mock.MagicMock()
        ase._client.primary_endpoint = 'ep'
        ase._name = 'name'
        ase._vio = None
        key = ops.Downloader.create_unique_transfer_operation_id(ase)
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('c')))
        dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
        dd.finalize_file = mock.MagicMock()
        dd.write_unchecked_hmac_data = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        d._crypto_offload = mock.MagicMock()
        d._crypto_offload.add_decrypt_chunk = mock.MagicMock()
        d._dd_map[str(lp)] = dd
        d._transfer_set.add(key)
        d._transfer_queue = mock.MagicMock()
        d._transfer_queue.get.side_effect = [dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_transfer()
        assert len(d._disk_set) == 1
        a, b, c = d._disk_queue.get()
        d._process_data(a, b, c)
        assert d._crypto_offload.add_decrypt_chunk.call_count == 1
        assert dd.write_unchecked_hmac_data.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.crypto_processes = 0
        d._general_options.concurrency.transfer_threads = 1
        d._general_options.concurrency.disk_threads = 1
        opts = mock.MagicMock()
        opts.check_file_md5 = False
        opts.chunk_size_bytes = 16
        ase = azmodels.StorageEntity('cont')
        ase._mode = azmodels.StorageModes.Auto
        ase._size = 32
        ase._encryption = mock.MagicMock()
        ase._encryption.symmetric_key = b'abc'
        ase._encryption.content_encryption_iv = b'0' * 16
        ase._client = mock.MagicMock()
        ase._client.primary_endpoint = 'ep'
        ase._name = 'name'
        ase._vio = None
        key = ops.Downloader.create_unique_transfer_operation_id(ase)
        patched_gfr.return_value = b'0' * ase._size
        lp = pathlib.Path(str(tmpdir.join('d')))
        dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
        dd.next_offsets()
        dd.write_unchecked_hmac_data = mock.MagicMock()
        dd.perform_chunked_integrity_check = mock.MagicMock()
        dd.mark_unchecked_chunk_decrypted = mock.MagicMock()
        patched_acdd.return_value = b'0' * 16
        d._dd_map[str(lp)] = mock.MagicMock()
        d._transfer_set.add(key)
        d._transfer_queue = mock.MagicMock()
        d._transfer_queue.get.side_effect = [dd, dd]
        patched_tc.side_effect = [False, True]
        d._worker_thread_transfer()
        assert len(d._disk_set) == 1
        a, b, c = d._disk_queue.get()
        d._process_data(a, b, c)
        assert patched_acdd.call_count == 1
        assert dd.write_unchecked_hmac_data.call_count == 1
        assert dd.perform_chunked_integrity_check.call_count == 1


def test_worker_thread_disk():
    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.disk_threads = 1

        d._disk_queue = mock.MagicMock()
        d._disk_queue.get.side_effect = [
            (mock.MagicMock(), mock.MagicMock(), mock.MagicMock()),
        ]
        d._process_data = mock.MagicMock()
        patched_tc.side_effect = [False, True]

        d._worker_thread_disk()
        assert d._process_data.call_count == 1

    with mock.patch(
            'blobxfer.operations.download.Downloader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        d = ops.Downloader(
            mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
        d._general_options.concurrency.disk_threads = 1

        d._disk_queue = mock.MagicMock()
        d._disk_queue.get.side_effect = [
            (mock.MagicMock(), mock.MagicMock(), mock.MagicMock()),
        ]
        d._process_data = mock.MagicMock()
        d._process_data.side_effect = Exception()
        patched_tc.side_effect = [False, True]

        d._worker_thread_disk()
        assert len(d._exceptions) == 1


def test_cleanup_temporary_files(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
    dd._allocate_disk_space()
    dd.cleanup_all_temporary_files = mock.MagicMock()
    dd.cleanup_all_temporary_files.side_effect = Exception
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = pathlib.Path('abc')
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert dd.final_path.exists()

    lp = pathlib.Path(str(tmpdir.join('b')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
    dd._allocate_disk_space()
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert not dd.final_path.exists()

    lp = pathlib.Path(str(tmpdir.join('c')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    dd = models.Descriptor(lp, ase, opts, mock.MagicMock(), None)
    dd._allocate_disk_space()
    dd.cleanup_all_temporary_files = mock.MagicMock()
    dd.cleanup_all_temporary_files.side_effect = Exception
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._dd_map[0] = dd
    d._cleanup_temporary_files()
    assert dd.final_path.exists()


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


def _create_downloader_for_start(td):
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._cleanup_temporary_files = mock.MagicMock()
    d._download_start = datetime.datetime.now(tz=dateutil.tz.tzlocal())
    d._initialize_transfer_threads = mock.MagicMock()
    d._general_options.concurrency.crypto_processes = 1
    d._general_options.concurrency.md5_processes = 1
    d._general_options.concurrency.disk_threads = 1
    d._general_options.concurrency.transfer_threads = 1
    d._general_options.resume_file = pathlib.Path(str(td.join('rf')))
    d._spec.sources = []
    d._spec.options = mock.MagicMock()
    d._spec.options.chunk_size_bytes = 1
    d._spec.options.mode = azmodels.StorageModes.Auto
    d._spec.options.overwrite = True
    d._spec.options.rename = False
    d._spec.skip_on = mock.MagicMock()
    d._spec.skip_on.md5_match = False
    d._spec.skip_on.lmt_ge = False
    d._spec.skip_on.filesize_match = False
    d._spec.destination = mock.MagicMock()
    d._spec.destination.path = pathlib.Path(str(td))
    d._download_start_time = util.datetime_now()
    d._pre_md5_skip_on_check = mock.MagicMock()
    d._check_download_conditions = mock.MagicMock()
    d._all_remote_files_processed = False

    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    d._spec.sources.append(asp)

    return d


@mock.patch('blobxfer.operations.md5.LocalFileMd5Offload')
@mock.patch('blobxfer.operations.azure.blob.list_blobs')
@mock.patch(
    'blobxfer.operations.download.Downloader.ensure_local_destination',
    return_value=True
)
@mock.patch(
    'blobxfer.operations.download.Downloader.'
    'create_unique_transfer_operation_id',
    return_value='id'
)
@mock.patch(
    'blobxfer.operations.download.Downloader._wait_for_transfer_threads',
    return_value=None
)
@mock.patch(
    'blobxfer.operations.download.Downloader._wait_for_disk_threads',
    return_value=None
)
@mock.patch(
    'blobxfer.operations.crypto.CryptoOffload', return_value=mock.MagicMock())
def test_start(
        patched_crypto, patched_wdt, patched_wtt, patched_cutoi, patched_eld,
        patched_lb, patched_lfmo, tmpdir):
    patched_lfmo._check_thread = mock.MagicMock()

    b = azure.storage.blob.models.Blob(name='remote/path/name')
    b.properties.content_length = 1
    patched_lb.side_effect = [[b]]
    d = _create_downloader_for_start(tmpdir)
    d._check_download_conditions.return_value = ops.DownloadAction.Skip
    d._download_sofar = -1
    d._download_bytes_sofar = -1
    d.start()
    assert d._pre_md5_skip_on_check.call_count == 0

    patched_lb.side_effect = [[b]]
    d = _create_downloader_for_start(tmpdir)
    d._check_download_conditions.return_value = ops.DownloadAction.CheckMd5
    d._download_sofar = -1
    with pytest.raises(RuntimeError):
        d.start()
    d._download_terminate = True
    assert d._pre_md5_skip_on_check.call_count == 1

    b.properties.content_length = 0
    patched_lb.side_effect = [[b]]
    d = _create_downloader_for_start(tmpdir)
    d._check_download_conditions.return_value = ops.DownloadAction.Download
    with pytest.raises(RuntimeError):
        d.start()
    d._download_terminate = True
    assert d._transfer_queue.qsize() == 1

    # test exception count
    b = azure.storage.blob.models.Blob(name='name')
    b.properties.content_length = 1
    patched_lb.side_effect = [[b]]
    d = _create_downloader_for_start(tmpdir)
    d._spec.destination.is_dir = False
    d._spec.options.rename = True
    d._check_download_conditions.return_value = ops.DownloadAction.Skip
    d._exceptions = [RuntimeError('oops')]
    with pytest.raises(RuntimeError):
        d.start()
    d._download_terminate = True
    assert d._pre_md5_skip_on_check.call_count == 0


def test_start_exception():
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._run = mock.MagicMock(side_effect=RuntimeError('oops'))
    d._wait_for_transfer_threads = mock.MagicMock()
    d._cleanup_temporary_files = mock.MagicMock()
    d._md5_offload = mock.MagicMock()

    with pytest.raises(RuntimeError):
        d.start()
    assert d._wait_for_transfer_threads.call_count == 1
    assert d._cleanup_temporary_files.call_count == 1


def test_start_keyboard_interrupt():
    d = ops.Downloader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    d._general_options.resume_file = None
    d._run = mock.MagicMock(side_effect=KeyboardInterrupt)
    d._wait_for_transfer_threads = mock.MagicMock()
    d._cleanup_temporary_files = mock.MagicMock()
    d._md5_offload = mock.MagicMock()

    d.start()
    assert d._wait_for_transfer_threads.call_count == 1
    assert d._cleanup_temporary_files.call_count == 1
