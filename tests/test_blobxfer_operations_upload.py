# coding=utf-8
"""Tests for upload operations"""

# stdlib imports
import datetime
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import azure.storage.blob
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.upload as models
import blobxfer.util as util
# module under test
import blobxfer.operations.upload as ops


def test_termination_check():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    assert not u.termination_check
    assert not u.termination_check_md5


def test_create_unique_id():
    src = mock.MagicMock()
    src.absolute_path = 'abspath'
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'

    id = ops.Uploader.create_unique_id(src, ase)
    assert id == 'abspath;ep;asepath'


def test_create_unique_transfer_id():
    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    offsets = mock.MagicMock()
    offsets.range_start = 10
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'

    id = ops.Uploader.create_unique_transfer_id(lp, ase, offsets)
    assert id == 'lpabspath;ep;asepath;0;10'


def test_create_destination_id():
    client = mock.MagicMock()
    client.primary_endpoint = 'ep'

    id = ops.Uploader.create_destination_id(client, 'cont', 'name')
    assert id == 'ep;cont;name'


def test_append_slice_suffix_to_name():
    name = ops.Uploader.append_slice_suffix_to_name('name', 0)
    assert name == 'name.bxslice-0'


def test_update_progress_bar():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    with mock.patch(
            'blobxfer.operations.progress.update_progress_bar') as patched_upb:
        u._all_files_processed = False
        u._update_progress_bar()
        assert patched_upb.call_count == 0

        u._all_files_processed = True
        u._update_progress_bar()
        assert patched_upb.call_count == 1


def test_pre_md5_skip_on_check():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    src = mock.MagicMock()
    src.absolute_path = 'abspath'
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'

    u._md5_offload = mock.MagicMock()

    u._pre_md5_skip_on_check(src, ase)
    assert len(u._md5_map) == 1
    assert u._md5_offload.add_localfile_for_md5_check.call_count == 1


def test_post_md5_skip_on_check():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    src = mock.MagicMock()
    src.absolute_path = 'abspath'
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'

    id = ops.Uploader.create_unique_id(src, ase)
    u._md5_map[id] = (src, ase)
    u._upload_set.add(id)
    u._upload_total += 1

    u._general_options.dry_run = True
    u._post_md5_skip_on_check(id, True)
    assert len(u._md5_map) == 0
    assert id not in u._upload_set
    assert u._upload_total == 0

    u._general_options.dry_run = False
    u._md5_map[id] = (src, ase)
    u._upload_set.add(id)
    u._upload_total += 1
    u._add_to_upload_queue = mock.MagicMock()
    u._post_md5_skip_on_check(id, False)
    assert len(u._md5_map) == 0
    assert id in u._upload_set
    assert u._upload_total == 1
    assert u._add_to_upload_queue.call_count == 1

    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = True
    u._md5_map[id] = (src, ase)
    u._upload_set.add(id)
    u._upload_total += 1
    u._add_to_upload_queue = mock.MagicMock()
    u._post_md5_skip_on_check(id, False)
    assert len(u._md5_map) == 0
    assert id not in u._upload_set
    assert u._upload_total == 0


def test_check_for_uploads_from_md5():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._md5_offload = mock.MagicMock()
    u._post_md5_skip_on_check = mock.MagicMock()

    with mock.patch(
            'blobxfer.operations.upload.Uploader.termination_check_md5',
            new_callable=mock.PropertyMock) as patched_tcm:
        patched_tcm.side_effect = [False, False, False, True, True]
        u._md5_offload.pop_done_queue.side_effect = [
            None, mock.MagicMock(), None
        ]

        u._check_for_uploads_from_md5()
        assert u._post_md5_skip_on_check.call_count == 1


def test_add_to_upload_queue():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._spec.options.chunk_size_bytes = 32

    src = mock.MagicMock()
    src.absolute_path = 'abspath'
    src.size = 32
    src.use_stdin = False
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.encryption_metadata.symmetric_key = 'abc'
    id = ops.Uploader.create_unique_id(src, ase)

    u._add_to_upload_queue(src, ase, id)
    assert len(u._ud_map) == 1
    assert u._upload_queue.qsize() == 1
    assert u._upload_start_time is not None


def test_initialize_disk_threads():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1

    try:
        u._initialize_disk_threads()
        assert len(u._disk_threads) == 1
    finally:
        u._wait_for_disk_threads(True)
        for thr in u._disk_threads:
            assert not thr.is_alive()


def test_initialize_transfer_threads():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1

    try:
        u._initialize_transfer_threads()
        assert len(u._transfer_threads) == 1
    finally:
        u._wait_for_transfer_threads(True)
        for thr in u._transfer_threads:
            assert not thr.is_alive()


def test_worker_thread_transfer():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._transfer_queue.put(
        (mock.MagicMock, mock.MagicMock, mock.MagicMock, mock.MagicMock)
    )
    u._transfer_queue.put(
        (mock.MagicMock, mock.MagicMock, mock.MagicMock, mock.MagicMock)
    )
    u._process_transfer = mock.MagicMock()
    u._process_transfer.side_effect = [None, Exception()]

    with mock.patch(
            'blobxfer.operations.upload.Uploader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        patched_tc.side_effect = [False, False, True]
        u._worker_thread_transfer()
        assert u._process_transfer.call_count == 2
        assert len(u._exceptions) == 1


def test_process_transfer():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._put_data = mock.MagicMock()
    u._update_progress_bar = mock.MagicMock()

    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = True

    ud = mock.MagicMock()
    ud.entity.mode = azmodels.StorageModes.Append
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp

    id = ops.Uploader.create_unique_transfer_id(lp, ase, offsets)
    u._transfer_set.add(id)

    u._process_transfer(ud, ase, offsets, mock.MagicMock())
    assert u._upload_bytes_total == 1
    assert u._upload_bytes_sofar == 1
    assert len(u._transfer_set) == 0
    assert ud.complete_offset_upload.call_count == 1
    assert u._upload_queue.qsize() == 1
    assert u._update_progress_bar.call_count == 1

    lp.use_stdin = False
    u._transfer_set.add(id)
    u._process_transfer(ud, ase, offsets, mock.MagicMock())
    assert u._upload_bytes_total == 11
    assert u._upload_bytes_sofar == 2
    assert len(u._transfer_set) == 0
    assert ud.complete_offset_upload.call_count == 2
    assert u._upload_queue.qsize() == 2
    assert u._update_progress_bar.call_count == 2


@mock.patch('blobxfer.operations.azure.blob.append.append_block')
@mock.patch('blobxfer.operations.azure.blob.block.create_blob')
@mock.patch('blobxfer.operations.azure.blob.block.put_block')
@mock.patch('blobxfer.operations.azure.file.put_file_range')
@mock.patch('blobxfer.operations.azure.blob.page.put_page')
def test_put_data(pp, pfr, pb, cb, ab):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = True

    ud = mock.MagicMock()
    ud.entity.mode = azmodels.StorageModes.Append
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp

    ase.mode = azmodels.StorageModes.Append
    u._put_data(ud, ase, offsets, b'\0')
    assert ab.call_count == 1

    ase.mode = azmodels.StorageModes.Block
    ud.is_one_shot_block_blob = True
    ud.entity.is_encrypted = False
    ud.must_compute_md5 = True
    ud.md5.digest.return_value = b'md5'
    u._put_data(ud, ase, offsets, b'\0')
    assert cb.call_count == 1

    ud.must_compute_md5 = False
    u._put_data(ud, ase, offsets, b'\0')
    assert cb.call_count == 2

    ud.is_one_shot_block_blob = False
    u._put_data(ud, ase, offsets, b'\0')
    assert pb.call_count == 1

    ase.mode = azmodels.StorageModes.File
    u._put_data(ud, ase, offsets, b'\0')
    assert pfr.call_count == 1

    ase.mode = azmodels.StorageModes.Page
    u._put_data(ud, ase, offsets, None)
    assert pp.call_count == 0

    ase.mode = azmodels.StorageModes.Page
    u._put_data(ud, ase, offsets, b'\0')
    assert pp.call_count == 0

    ase.mode = azmodels.StorageModes.Page
    u._put_data(ud, ase, offsets, b'1')
    assert pp.call_count == 1


@mock.patch('time.sleep', return_value=None)
def test_worker_thread_upload(ts):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._general_options.concurrency.transfer_threads = 1

    u._transfer_set = mock.MagicMock()
    u._transfer_set.__len__.side_effect = [5, 0, 0, 0]
    u._upload_queue.put(mock.MagicMock)
    u._upload_queue.put(mock.MagicMock)
    u._process_upload_descriptor = mock.MagicMock()
    u._process_upload_descriptor.side_effect = [None, Exception()]

    with mock.patch(
            'blobxfer.operations.upload.Uploader.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        patched_tc.side_effect = [False, False, False, False, True]
        u._worker_thread_upload()
        assert u._process_upload_descriptor.call_count == 2
        assert len(u._exceptions) == 1


@mock.patch('blobxfer.operations.azure.blob.create_container')
@mock.patch('blobxfer.operations.azure.blob.append.create_blob')
@mock.patch('blobxfer.operations.azure.file.create_share')
@mock.patch('blobxfer.operations.azure.file.create_all_parent_directories')
@mock.patch('blobxfer.operations.azure.file.create_file')
@mock.patch('blobxfer.operations.azure.blob.page.create_blob')
def test_prepare_upload(page_cb, cf, capd, cs, append_cb, cc):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10

    ase.mode = azmodels.StorageModes.Append
    ase.append_create = True
    u._prepare_upload(ase)
    assert cc.call_count == 1
    assert append_cb.call_count == 1

    ase.mode = azmodels.StorageModes.Block
    ase.append_create = False
    u._prepare_upload(ase)
    assert cc.call_count == 2

    ase.mode = azmodels.StorageModes.File
    u._prepare_upload(ase)
    assert cs.call_count == 1
    assert capd.call_count == 1
    assert cf.call_count == 1

    ase.mode = azmodels.StorageModes.Page
    u._prepare_upload(ase)
    assert cc.call_count == 3
    assert page_cb.call_count == 1


def test_process_upload_descriptor():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = True

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.next_offsets.return_value = (None, 1)
    ud.all_operations_completed = True
    ud.unique_id = 'uid'

    u._finalize_upload = mock.MagicMock()
    u._ud_map['uid'] = 0
    u._upload_set.add('uid')

    # test resume and completed
    u._process_upload_descriptor(ud)
    assert u._upload_bytes_total == 10
    assert u._upload_bytes_sofar == 1
    assert u._finalize_upload.call_count == 1
    assert len(u._ud_map) == 0
    assert len(u._upload_set) == 0
    assert u._upload_sofar == 1

    # test nothing
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    ud.all_operations_completed = False
    ud.next_offsets.return_value = (None, None)
    u._process_upload_descriptor(ud)
    assert u._upload_queue.qsize() == 1

    # test encrypted
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10
    ud.next_offsets.return_value = (offsets, None)
    u._prepare_upload = mock.MagicMock()
    ase2 = mock.MagicMock()
    ase2._client.primary_endpoint = 'ep'
    ase2.path = 'asepath2'
    ase2.size = 10
    ase2.mode = azmodels.StorageModes.Block
    ase.replica_targets = [ase2]
    ase.is_encrypted = True
    ud.read_data.return_value = (b'\0', None)

    with mock.patch(
            'blobxfer.operations.crypto.aes_cbc_encrypt_data',
            return_value=b'\0' * 16):
        u._process_upload_descriptor(ud)
        assert u._upload_queue.qsize() == 1
        assert u._prepare_upload.call_count == 2
        assert ud.hmac_data.call_count == 2
        assert u._transfer_queue.qsize() == 2
        assert len(u._transfer_set) == 2

    # test stdin
    ase.is_encrypted = False
    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = True
    ud.local_path = lp

    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._prepare_upload = mock.MagicMock()
    ud.read_data.return_value = (False, offsets)
    u._process_upload_descriptor(ud)
    assert u._upload_queue.qsize() == 1
    assert u._transfer_queue.qsize() == 0
    assert len(u._transfer_set) == 0


@mock.patch('blobxfer.operations.azure.blob.block.put_block_list')
def test_finalize_block_blob(pbl):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.unique_id = 'uid'
    ud.must_compute_md5 = True
    ud.md5.digest.return_value = b'md5'

    u._finalize_block_blob(ud, mock.MagicMock())
    assert pbl.call_count == 2

    ud.must_compute_md5 = False
    ase.replica_targets = []
    u._finalize_block_blob(ud, mock.MagicMock())
    assert pbl.call_count == 3


@mock.patch('blobxfer.operations.azure.blob.set_blob_properties')
def test_set_blob_properties(sbp):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.unique_id = 'uid'
    ud.must_compute_md5 = True
    ud.md5.digest.return_value = b'md5'

    u._set_blob_properties(ud)
    assert sbp.call_count == 2

    ud.requires_non_encrypted_md5_put = False
    ud.must_compute_md5 = False
    ase.cache_control = 'cc'

    u._set_blob_properties(ud)
    assert sbp.call_count == 4


@mock.patch('blobxfer.operations.azure.blob.set_blob_metadata')
def test_set_blob_metadata(sbm):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.unique_id = 'uid'

    u._set_blob_metadata(ud, mock.MagicMock())
    assert sbm.call_count == 2


@mock.patch('blobxfer.operations.azure.blob.page.resize_blob')
def test_resize_blob(rb):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = True

    ud = mock.MagicMock()
    ud.entity = ase
    ud.local_path = lp
    ud.unique_id = 'uid'

    u._resize_blob(ud, 512)
    assert rb.call_count == 2


def test_finalize_nonblock_blob():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.local_path = lp
    ud.unique_id = 'uid'
    ud.requires_non_encrypted_md5_put = True
    ud.requires_resize.return_value = (False, None)

    u._set_blob_properties = mock.MagicMock()
    u._set_blob_metadata = mock.MagicMock()
    u._resize_blob = mock.MagicMock()

    u._finalize_nonblock_blob(ud, {'a': 0})
    assert u._set_blob_properties.call_count == 1
    assert u._set_blob_metadata.call_count == 1
    assert u._resize_blob.call_count == 0

    # resize required
    ud.requires_resize.return_value = (True, 512)
    u._finalize_nonblock_blob(ud, {'a': 0})
    assert u._resize_blob.call_count == 1


@mock.patch('blobxfer.operations.azure.file.set_file_properties')
@mock.patch('blobxfer.operations.azure.file.set_file_metadata')
def test_finalize_azure_file(sfmeta, sfp):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.File
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.unique_id = 'uid'
    ud.must_compute_md5 = True
    ud.md5.digest.return_value = b'md5'
    ud.requires_non_encrypted_md5_put = True

    u._finalize_azure_file(ud, {'a': 0})
    assert sfp.call_count == 2
    assert sfmeta.call_count == 2

    ud.requires_non_encrypted_md5_put = False
    ud.must_compute_md5 = False
    ase.cache_control = 'cc'

    u._finalize_azure_file(ud, {'a': 0})
    assert sfp.call_count == 4


def test_finalize_upload():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    lp = mock.MagicMock()
    lp.absolute_path = 'lpabspath'
    lp.view.fd_start = 0
    lp.use_stdin = False

    ud = mock.MagicMock()
    ud.entity = ase
    ud.complete_offset_upload = mock.MagicMock()
    ud.local_path = lp
    ud.unique_id = 'uid'
    ud.requires_put_block_list = True

    u._finalize_block_blob = mock.MagicMock()
    u._finalize_upload(ud)
    assert u._finalize_block_blob.call_count == 1

    ud.requires_put_block_list = False
    ud.remote_is_page_blob = True
    u._finalize_nonblock_blob = mock.MagicMock()
    u._finalize_upload(ud)
    assert u._finalize_nonblock_blob.call_count == 1

    ud.remote_is_page_blob = False
    ud.remote_is_append_blob = False
    ud.remote_is_file = True
    u._finalize_azure_file = mock.MagicMock()
    u._finalize_upload(ud)
    assert u._finalize_azure_file.call_count == 1


def test_get_destination_paths():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    paths = mock.MagicMock()
    paths.paths = [pathlib.Path('a/b')]
    u._spec.destinations = [paths]

    sa, cont, dir, dpath = next(u._get_destination_paths())
    assert cont == 'a'
    assert dir == 'b'
    assert dpath == pathlib.Path('a/b')


@mock.patch('blobxfer.operations.azure.file.list_all_files')
@mock.patch('blobxfer.operations.azure.file.delete_file')
@mock.patch('blobxfer.operations.azure.blob.list_all_blobs')
@mock.patch('blobxfer.operations.azure.blob.delete_blob')
def test_delete_extraneous_files(db, lab, df, laf):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    # test no delete
    u._spec.options.delete_extraneous_destination = False
    u._get_destination_paths = mock.MagicMock()

    u._delete_extraneous_files()
    assert u._get_destination_paths.call_count == 0

    # test file delete
    u._spec.options.delete_extraneous_destination = True
    u._spec.options.mode = azmodels.StorageModes.File

    sa1 = mock.MagicMock()
    sa1.name = 'name'
    sa1.endpoint = 'ep'
    sa1.file_client.primary_endpoint = 'ep'

    laf.return_value = ['filename']

    # test relative path failure
    u._get_destination_paths = mock.MagicMock()
    u._get_destination_paths.return_value = [
        (sa1, 'cont', 'vpath', ''),
    ]
    u._delete_extraneous_files()
    assert laf.call_count == 1
    assert df.call_count == 0

    # test actual delete
    u._get_destination_paths = mock.MagicMock()
    u._get_destination_paths.return_value = [
        (sa1, 'cont', '', ''),
        (sa1, 'cont', '', ''),
    ]

    u._general_options.dry_run = True
    u._delete_extraneous_files()
    assert laf.call_count == 2
    assert df.call_count == 0

    u._general_options.dry_run = False
    u._delete_extraneous_files()
    assert laf.call_count == 3
    assert df.call_count == 1

    # test blob delete
    u._spec.options.delete_extraneous_destination = True
    u._spec.options.mode = azmodels.StorageModes.Block

    sa1 = mock.MagicMock()
    sa1.name = 'name'
    sa1.endpoint = 'ep'
    sa1.block_blob_client.primary_endpoint = 'ep'

    blob = mock.MagicMock()
    blob.name = 'blobname'
    lab.return_value = [blob]

    # test relative path failure
    u._get_destination_paths = mock.MagicMock()
    u._get_destination_paths.return_value = [
        (sa1, 'cont', 'vpath', ''),
    ]
    u._delete_extraneous_files()
    assert lab.call_count == 1
    assert db.call_count == 0

    # test actual delete
    u._get_destination_paths = mock.MagicMock()
    u._get_destination_paths.return_value = [
        (sa1, 'cont', '', ''),
    ]

    u._general_options.dry_run = True
    u._delete_extraneous_files()
    assert lab.call_count == 2
    assert db.call_count == 0

    u._general_options.dry_run = False
    u._delete_extraneous_files()
    assert lab.call_count == 3
    assert db.call_count == 1


@mock.patch('blobxfer.models.metadata.get_md5_from_metadata')
def test_check_upload_conditions(gmfm):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.append_create = True
    ase.is_encrypted = False
    ase.from_local = False

    lp = mock.MagicMock()
    lp.absolute_path = pathlib.Path('lpabspath')
    lp.view.fd_start = 0
    lp.use_stdin = False

    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Skip

    lp.use_stdin = True
    assert u._check_upload_conditions(lp, None) == ops.UploadAction.Upload

    u._spec.options.overwrite = False
    ase.mode = azmodels.StorageModes.Append
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Upload
    assert not ase.append_create

    ase.mode = azmodels.StorageModes.Block
    ase.append_create = True
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Skip
    assert ase.append_create

    u._spec.options.overwrite = True
    u._spec.skip_on.md5_match = True
    gmfm.return_value = 'md5'
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.CheckMd5

    u._spec.skip_on.md5_match = False
    u._spec.skip_on.filesize_match = False
    u._spec.skip_on.lmt_ge = False
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Upload

    # size mismatch, page
    u._spec.skip_on.filesize_match = True
    ase.mode = azmodels.StorageModes.Page
    lp.size = 1
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Upload

    # size match
    u._spec.skip_on.filesize_match = True
    ase.mode = azmodels.StorageModes.Block
    lp.size = ase.size
    assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Skip

    # lmt match
    u._spec.skip_on.filesize_match = False
    u._spec.skip_on.lmt_ge = True
    ase.lmt = 0
    with mock.patch('blobxfer.util.datetime_from_timestamp') as patched_dft:
        patched_dft.return_value = 0
        assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Skip

    # lmt mismatch
    u._spec.skip_on.lmt_ge = True
    ase.lmt = 0
    with mock.patch('blobxfer.util.datetime_from_timestamp') as patched_dft:
        patched_dft.return_value = 1
        assert u._check_upload_conditions(lp, ase) == ops.UploadAction.Upload


@mock.patch('blobxfer.operations.azure.file.get_file_properties')
@mock.patch('blobxfer.operations.azure.blob.get_blob_properties')
def test_check_for_existing_remote(gbp, gfp):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'

    u._spec.options.mode = azmodels.StorageModes.File
    gfp.return_value = None
    assert u._check_for_existing_remote(sa, 'cont', 'name') is None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=False):
        gfp.return_value = mock.MagicMock()
        assert u._check_for_existing_remote(sa, 'cont', 'name') is not None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=True):
        with mock.patch(
                'blobxfer.models.crypto.EncryptionMetadata.convert_from_json'):
            gfp.return_value = mock.MagicMock()
            assert u._check_for_existing_remote(sa, 'cont', 'name') is not None

    u._spec.options.mode = azmodels.StorageModes.Block
    gbp.return_value = None
    assert u._check_for_existing_remote(sa, 'cont', 'name') is None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=False):
        gbp.return_value = mock.MagicMock()
        assert u._check_for_existing_remote(sa, 'cont', 'name') is not None

    # check access tiers
    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=False):
        gbp.return_value = mock.MagicMock()
        gbp.return_value.properties.blob_type = \
            azure.storage.blob.models._BlobTypes.BlockBlob
        gbp.return_value.properties.blob_tier = None

        u._spec.options.access_tier = None
        ase = u._check_for_existing_remote(sa, 'cont', 'name')
        assert ase is not None
        assert ase.access_tier is None

        gbp.return_value.properties.blob_tier = 'Cool'
        ase = u._check_for_existing_remote(sa, 'cont', 'name')
        assert ase is not None
        assert ase.access_tier is None

        u._spec.options.access_tier = 'Hot'
        ase = u._check_for_existing_remote(sa, 'cont', 'name')
        assert ase is not None
        assert ase.access_tier == 'Hot'


def test_generate_destination_for_source():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._check_for_existing_remote = mock.MagicMock()

    lp = mock.MagicMock()
    lp.relative_path = pathlib.Path('a/b/c/d')
    lp.absolute_path = pathlib.Path('abs/rel/a/b/c/d')
    lp.view.fd_start = 0
    lp.use_stdin = False

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'

    u._spec.options.strip_components = 1
    u._spec.options.rename = True
    u._get_destination_paths = mock.MagicMock()
    u._get_destination_paths.return_value = [
        (sa, 'cont', '', 'dpath'),
    ]

    with pytest.raises(ValueError):
        next(u._generate_destination_for_source(lp))

    lp.relative_path = pathlib.Path('rel/a')
    lp.absolute_path = pathlib.Path('abs/rel/a')

    u._spec.options.strip_components = 0
    u._spec.options.rename = False
    u._get_destination_paths.return_value = [
        (sa, 'cont', 'name', 'dpath'),
    ]
    u._spec.options.mode = azmodels.StorageModes.Block
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Stripe
    a, b = next(u._generate_destination_for_source(lp))
    assert a == sa
    assert b is not None
    assert u._check_for_existing_remote.call_count == 0

    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Disabled
    a, b = next(u._generate_destination_for_source(lp))
    assert a == sa
    assert b is not None
    assert u._check_for_existing_remote.call_count == 1

    # check no-read permission
    sa.can_read_object = False
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Disabled
    a, b = next(u._generate_destination_for_source(lp))
    assert a == sa
    assert b is not None
    assert u._check_for_existing_remote.call_count == 1  # should not change


def test_vectorize_and_bind():
    ase = mock.MagicMock()
    ase.client.primary_endpoint = 'ep'
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = None
    ase.container = 'cont'
    ase.name = 'name'

    ase2 = mock.MagicMock()
    ase2.client.primary_endpoint = 'ep2'
    ase2._client.primary_endpoint = 'ep2'
    ase2.path = 'asepath2'
    ase2.mode = azmodels.StorageModes.Block
    ase2.is_encrypted = False
    ase2.replica_targets = None
    ase2.container = 'cont2'
    ase2.name = 'name2'

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'
    sa.block_blob_client.primary_endpoint = 'pep'

    lp = mock.MagicMock()
    lp.relative_path = pathlib.Path('rel/a')
    lp.absolute_path = pathlib.Path('abs/rel/a')
    lp.view.fd_start = 0
    lp.use_stdin = False
    lp.total_size = 9

    # no vectorization
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Disabled
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Upload

    dest = [(sa, ase)]

    a, b, c = next(u._vectorize_and_bind(lp, dest))
    assert a == ops.UploadAction.Upload
    assert b == lp
    assert c == ase

    # sub-test no object write
    sa.can_write_object = False
    dest = [(sa, ase)]
    with pytest.raises(RuntimeError):
        a, b, c = next(u._vectorize_and_bind(lp, dest))
    sa.can_write_object = True

    # stripe vectorization 1 slice
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Upload
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Stripe
    u._spec.options.vectored_io.stripe_chunk_size_bytes = 10

    dest = [(sa, ase), (sa, ase2)]

    i = 0
    for a, b, c in u._vectorize_and_bind(lp, dest):
        assert a == ops.UploadAction.Upload
        assert b == lp
        assert c == ase
        i += 1
    assert i == 1

    # sub-test no object write
    sa.can_write_object = False
    dest = [(sa, ase), (sa, ase2)]
    with pytest.raises(RuntimeError):
        a, b, c = next(u._vectorize_and_bind(lp, dest))
    sa.can_write_object = True

    # stripe vectorization multi-slice
    u._spec.options.mode = azmodels.StorageModes.Block
    u._spec.options.vectored_io.stripe_chunk_size_bytes = 5
    u._check_for_existing_remote = mock.MagicMock()
    u._check_for_existing_remote.return_value = None

    dest = [(sa, ase), (sa, ase2)]

    i = 0
    for a, b, c in u._vectorize_and_bind(lp, dest):
        assert a == ops.UploadAction.Upload
        assert b != lp
        assert b.parent_path == lp.parent_path
        assert b.relative_path == lp.relative_path
        assert not b.use_stdin
        if i == 0:
            assert b.view.fd_start == 0
            assert b.view.fd_end == 5
            assert b.view.slice_num == 0
        else:
            assert b.view.fd_start == 5
            assert b.view.fd_end == 9
            assert b.view.slice_num == 1
        assert b.view.mode == u._spec.options.vectored_io.distribution_mode
        assert c != ase
        assert c.from_local
        i += 1
    assert i == 2

    # sub-test no object write
    sa.can_write_object = False
    dest = [(sa, ase), (sa, ase2)]
    with pytest.raises(RuntimeError):
        a, b, c = next(u._vectorize_and_bind(lp, dest))
    sa.can_write_object = True

    # replication single target
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Replica
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.CheckMd5

    dest = [(sa, ase)]

    a, b, c = next(u._vectorize_and_bind(lp, dest))
    assert a == ops.UploadAction.CheckMd5
    assert b == lp
    assert c == ase
    assert c.replica_targets is None

    # sub-test no object write
    sa.can_write_object = False
    dest = [(sa, ase)]
    with pytest.raises(RuntimeError):
        a, b, c = next(u._vectorize_and_bind(lp, dest))
    sa.can_write_object = True

    # replication multi-target md5
    dest = [(sa, ase), (sa, ase2)]

    a, b, c = next(u._vectorize_and_bind(lp, dest))
    assert a == ops.UploadAction.CheckMd5
    assert b == lp
    assert c == ase
    assert c.replica_targets is None

    # replication multi-target upload
    u._spec.options.delete_extraneous_destination = True
    u._check_upload_conditions.return_value = ops.UploadAction.Upload
    a, b, c = next(u._vectorize_and_bind(lp, dest))
    assert a == ops.UploadAction.Upload
    assert b == lp
    assert c == ase
    assert len(c.replica_targets) == 1
    assert c.replica_targets[0] == ase2


@mock.patch('blobxfer.operations.resume.UploadResumeManager')
@mock.patch('blobxfer.operations.md5.LocalFileMd5Offload')
def test_run(lfmo, urm, tmpdir):
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._initialize_disk_threads = mock.MagicMock()
    u._initialize_transfer_threads = mock.MagicMock()
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1
    u._general_options.concurrency.md5_processes = 1
    u._general_options.concurrency.crypto_processes = 1
    u._general_options.resume_file = 'resume'
    u._spec.options.store_file_properties.md5 = True
    u._spec.skip_on.md5_match = True
    u._spec.options.rsa_public_key = 'abc'
    u._spec.options.chunk_size_bytes = 0
    u._spec.options.one_shot_bytes = 0

    # check rename failure
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = True
    with pytest.raises(RuntimeError):
        u._run()
        u._upload_terminate = True
        assert urm.call_count == 0
        assert lfmo.call_count == 0
        assert lfmo.initialize_check_thread.call_count == 0
        assert u._initialize_disk_threads.call_count == 0
        assert u._initialize_transfer_threads.call_count == 0

    # check dupe
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = False

    ase = mock.MagicMock()
    ase.client.primary_endpoint = 'ep'
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = None
    ase.container = 'cont'
    ase.name = 'name'
    ase.size = 10

    ase2 = mock.MagicMock()
    ase2.client.primary_endpoint = 'ep2'
    ase2._client.primary_endpoint = 'ep2'
    ase2.path = 'asepath2'
    ase2.mode = azmodels.StorageModes.Block
    ase2.is_encrypted = False
    ase2.replica_targets = None
    ase2.container = 'cont2'
    ase2.name = 'name2'
    ase2.size = 10

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'
    sa.block_blob_client.primary_endpoint = 'pep'

    tmpdir.join('a').write('z' * 10)
    lp = mock.MagicMock()
    lp.relative_path = pathlib.Path('a')
    lp.absolute_path = pathlib.Path(str(tmpdir.join('a')))
    lp.view.fd_start = 0
    lp.view.fd_end = 10
    lp.use_stdin = False
    lp.size = 10
    lp.total_size = 10

    u._generate_destination_for_source = mock.MagicMock()
    with pytest.raises(RuntimeError):
        u._generate_destination_for_source.return_value = [
            (sa, ase), (sa, ase)
        ]
        u._spec.sources.files.return_value = [lp]

        u._run()
        u._upload_terminate = True
        assert urm.call_count == 1
        assert lfmo.call_count == 1
        assert u._md5_offload.initialize_check_thread.call_count == 1
        assert u._initialize_disk_threads.call_count == 1
        assert u._initialize_transfer_threads.call_count == 1

    # mismatch exception raise
    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Disabled
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Skip
    u._generate_destination_for_source.return_value = [
        (sa, ase)
    ]
    u._spec.sources.files.return_value = [lp]

    with pytest.raises(RuntimeError):
        u._run()
        u._upload_terminate = True

    u._check_upload_conditions.return_value = ops.UploadAction.CheckMd5
    with pytest.raises(RuntimeError):
        u._run()
        u._upload_terminate = True

    # regular execution
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1
    u._general_options.concurrency.md5_processes = 1
    u._general_options.concurrency.crypto_processes = 0
    u._general_options.resume_file = 'resume'
    u._spec.options.store_file_properties.md5 = True
    u._spec.skip_on.md5_match = True
    u._spec.options.rsa_public_key = None
    u._spec.options.chunk_size_bytes = 0
    u._spec.options.one_shot_bytes = 0
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = False

    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Replica
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Upload
    u._generate_destination_for_source = mock.MagicMock()
    u._generate_destination_for_source.return_value = [
        (sa, ase), (sa, ase2)
    ]
    u._spec.sources.files.return_value = [lp]
    u._put_data = mock.MagicMock()
    u._finalize_upload = mock.MagicMock()
    u._upload_start_time = (
        util.datetime_now() - datetime.timedelta(seconds=1)
    )
    u._run()
    assert u._finalize_upload.call_count == 1

    # regular execution, skip dry run
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = True
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1
    u._general_options.concurrency.md5_processes = 1
    u._general_options.concurrency.crypto_processes = 0
    u._general_options.resume_file = 'resume'
    u._spec.options.store_file_properties.md5 = True
    u._spec.skip_on.md5_match = True
    u._spec.options.rsa_public_key = None
    u._spec.options.chunk_size_bytes = 0
    u._spec.options.one_shot_bytes = 0
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = False

    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Replica
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Skip
    u._generate_destination_for_source = mock.MagicMock()
    u._generate_destination_for_source.return_value = [
        (sa, ase), (sa, ase2)
    ]
    u._spec.sources.files.return_value = [lp]
    u._put_data = mock.MagicMock()
    u._finalize_upload = mock.MagicMock()
    u._upload_start_time = (
        util.datetime_now() - datetime.timedelta(seconds=1)
    )
    u._run()
    assert u._finalize_upload.call_count == 0

    # regular execution, upload dry run
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = True
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1
    u._general_options.concurrency.md5_processes = 1
    u._general_options.concurrency.crypto_processes = 0
    u._general_options.resume_file = 'resume'
    u._spec.options.store_file_properties.md5 = True
    u._spec.skip_on.md5_match = True
    u._spec.options.rsa_public_key = None
    u._spec.options.chunk_size_bytes = 0
    u._spec.options.one_shot_bytes = 0
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = False

    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Replica
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Upload
    u._generate_destination_for_source = mock.MagicMock()
    u._generate_destination_for_source.return_value = [
        (sa, ase), (sa, ase2)
    ]
    u._spec.sources.files.return_value = [lp]
    u._put_data = mock.MagicMock()
    u._finalize_upload = mock.MagicMock()
    u._upload_start_time = (
        util.datetime_now() - datetime.timedelta(seconds=1)
    )
    u._run()
    assert u._finalize_upload.call_count == 0

    # exception raise
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._general_options.concurrency.disk_threads = 1
    u._general_options.concurrency.transfer_threads = 1
    u._general_options.concurrency.md5_processes = 1
    u._general_options.concurrency.crypto_processes = 0
    u._general_options.resume_file = 'resume'
    u._spec.options.store_file_properties.md5 = True
    u._spec.skip_on.md5_match = True
    u._spec.options.rsa_public_key = None
    u._spec.options.chunk_size_bytes = 0
    u._spec.options.one_shot_bytes = 0
    u._spec.sources.can_rename.return_value = False
    u._spec.options.rename = False

    u._spec.options.vectored_io.distribution_mode = \
        models.VectoredIoDistributionMode.Disabled
    u._check_upload_conditions = mock.MagicMock()
    u._check_upload_conditions.return_value = ops.UploadAction.Upload
    u._generate_destination_for_source = mock.MagicMock()
    u._generate_destination_for_source.return_value = [
        (sa, ase)
    ]
    u._spec.sources.files.return_value = [lp]

    with pytest.raises(RuntimeError):
        u._process_upload_descriptor = mock.MagicMock()
        u._process_upload_descriptor.side_effect = RuntimeError()
        u._run()
        u._upload_terminate = True


def test_start():
    u = ops.Uploader(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    u._general_options.dry_run = False
    u._wait_for_transfer_threads = mock.MagicMock()
    u._wait_for_disk_threads = mock.MagicMock()
    u._md5_offload = mock.MagicMock()
    u._md5_offload.finalize_processes = mock.MagicMock()
    u._crypto_offload = mock.MagicMock()
    u._crypto_offload.finalize_processes = mock.MagicMock()
    u._resume = mock.MagicMock()
    u._run = mock.MagicMock()

    # test keyboard interrupt
    u._run.side_effect = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        u.start()

    assert u._run.call_count == 1
    assert u._wait_for_transfer_threads.call_count == 1
    assert u._wait_for_disk_threads.call_count == 1
    assert u._md5_offload.finalize_processes.call_count == 1
    assert u._crypto_offload.finalize_processes.call_count == 1
    assert u._resume.close.call_count == 1

    # test other exception
    u._run.side_effect = RuntimeError()
    with pytest.raises(RuntimeError):
        u.start()

    assert u._run.call_count == 2
    assert u._wait_for_transfer_threads.call_count == 2
    assert u._wait_for_disk_threads.call_count == 2
    assert u._md5_offload.finalize_processes.call_count == 2
    assert u._crypto_offload.finalize_processes.call_count == 2
    assert u._resume.close.call_count == 2

    u._run.side_effect = RuntimeError()
    with pytest.raises(RuntimeError):
        u._wait_for_transfer_threads = mock.MagicMock(
            side_effect=RuntimeError('oops'))
        u._upload_terminate = True
        u.start()

    assert u._run.call_count == 3
    assert u._wait_for_transfer_threads.call_count == 1
    assert u._wait_for_disk_threads.call_count == 2
    assert u._md5_offload.finalize_processes.call_count == 3
    assert u._crypto_offload.finalize_processes.call_count == 3
    assert u._resume.close.call_count == 3
