# coding=utf-8
"""Tests for synccopy operations"""

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
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.util as util
# module under test
import blobxfer.operations.synccopy as ops


def test_termination_check():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    assert not s.termination_check


def test_create_unique_transfer_operation_id():
    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.path = 'dstasepath'

    id = ops.SyncCopy.create_unique_transfer_operation_id(src_ase, dst_ase)
    assert id == 'ep;srcasepath;ep2;dstasepath'


def test_create_deletion_id():
    client = mock.MagicMock()
    client.primary_endpoint = 'ep'

    id = ops.SyncCopy.create_deletion_id(client, 'cont', 'name')
    assert id == 'ep;cont;name'


def test_update_progress_bar():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    with mock.patch(
            'blobxfer.operations.progress.update_progress_bar') as patched_upb:
        s._update_progress_bar()
        assert patched_upb.call_count == 1


@mock.patch('blobxfer.operations.azure.file.list_all_files')
@mock.patch('blobxfer.operations.azure.file.delete_file')
@mock.patch('blobxfer.operations.azure.blob.list_all_blobs')
@mock.patch('blobxfer.operations.azure.blob.delete_blob')
def test_delete_extraneous_files(db, lab, df, laf):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    # test no delete
    s._spec.options.delete_extraneous_destination = False
    s._get_destination_paths = mock.MagicMock()

    s._delete_extraneous_files()
    assert s._get_destination_paths.call_count == 0

    # test file delete
    s._spec.options.delete_extraneous_destination = True
    s._spec.options.dest_mode = azmodels.StorageModes.File

    sa1 = mock.MagicMock()
    sa1.name = 'name'
    sa1.endpoint = 'ep'
    sa1.file_client.primary_endpoint = 'ep'

    s._get_destination_paths = mock.MagicMock()
    s._get_destination_paths.return_value = [
        (sa1, 'cont', None, None),
        (sa1, 'cont', None, None),
    ]

    laf.return_value = ['filename']

    s._delete_extraneous_files()
    assert laf.call_count == 1
    assert df.call_count == 1

    # test blob delete
    s._spec.options.delete_extraneous_destination = True
    s._spec.options.dest_mode = azmodels.StorageModes.Block

    sa1 = mock.MagicMock()
    sa1.name = 'name'
    sa1.endpoint = 'ep'
    sa1.block_blob_client.primary_endpoint = 'ep'

    s._get_destination_paths = mock.MagicMock()
    s._get_destination_paths.return_value = [
        (sa1, 'cont', None, None),
    ]

    blob = mock.MagicMock()
    blob.name = 'blobname'
    lab.return_value = [blob]

    s._delete_extraneous_files()
    assert lab.call_count == 1
    assert db.call_count == 1


@mock.patch('blobxfer.operations.azure.blob.block.get_committed_block_list')
def test_add_to_transfer_queue(gcbl):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Block

    gcbl.return_value = None
    s._add_to_transfer_queue(src_ase, dst_ase)
    assert gcbl.call_count == 1
    assert s._transfer_queue.qsize() == 1
    assert s._synccopy_start_time is not None

    src_ase.mode = azmodels.StorageModes.Page
    s._add_to_transfer_queue(src_ase, dst_ase)
    assert gcbl.call_count == 1
    assert s._transfer_queue.qsize() == 2
    assert s._synccopy_start_time is not None


def test_initialize_transfer_threads():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._general_options.concurrency.transfer_threads = 1

    try:
        s._initialize_transfer_threads()
        assert len(s._transfer_threads) == 1
    finally:
        s._wait_for_transfer_threads(True)
        for thr in s._transfer_threads:
            assert not thr.is_alive()


def test_worker_thread_transfer():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._transfer_queue.put(mock.MagicMock())
    s._transfer_queue.put(mock.MagicMock())
    s._process_synccopy_descriptor = mock.MagicMock()
    s._process_synccopy_descriptor.side_effect = [None, Exception()]

    with mock.patch(
            'blobxfer.operations.synccopy.SyncCopy.termination_check',
            new_callable=mock.PropertyMock) as patched_tc:
        patched_tc.side_effect = [False, False, True]
        s._worker_thread_transfer()
        assert s._process_synccopy_descriptor.call_count == 2
        assert len(s._exceptions) == 1


@mock.patch('blobxfer.operations.azure.blob.append.append_block')
@mock.patch('blobxfer.operations.azure.blob.block.create_blob')
@mock.patch('blobxfer.operations.azure.blob.block.put_block')
@mock.patch('blobxfer.operations.azure.file.put_file_range')
@mock.patch('blobxfer.operations.azure.blob.page.put_page')
def test_put_data(pp, pfr, pb, cb, ab):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10
    src_ase.is_encrypted = False

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Append
    dst_ase.size = 10
    dst_ase.is_encrypted = False

    sd = mock.MagicMock()
    sd.src_entity = src_ase
    sd.dst_entity = dst_ase
    sd.complete_offset_upload = mock.MagicMock()

    s._put_data(sd, dst_ase, offsets, b'\0')
    assert ab.call_count == 1

    dst_ase.mode = azmodels.StorageModes.Block
    sd.is_one_shot_block_blob = True
    sd.must_compute_md5 = True
    sd.src_entity.md5 = ''
    s._put_data(sd, dst_ase, offsets, b'\0')
    assert cb.call_count == 1

    sd.src_entity.md5 = b'md5'
    s._put_data(sd, dst_ase, offsets, b'\0')
    assert cb.call_count == 2

    sd.must_compute_md5 = False
    s._put_data(sd, dst_ase, offsets, b'\0')
    assert cb.call_count == 3

    sd.is_one_shot_block_blob = False
    s._put_data(sd, dst_ase, offsets, b'\0')
    assert pb.call_count == 1

    dst_ase.mode = azmodels.StorageModes.File
    s._put_data(sd, dst_ase, offsets, b'\0')
    assert pfr.call_count == 1

    dst_ase.mode = azmodels.StorageModes.Page
    s._put_data(sd, dst_ase, offsets, b'\0' * 512)
    assert pp.call_count == 0

    s._put_data(sd, dst_ase, offsets, b'1')
    assert pp.call_count == 1


def test_process_data():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    s._put_data = mock.MagicMock()
    s._complete_offset_upload = mock.MagicMock()
    offsets = mock.MagicMock()
    offsets.num_bytes = 1
    offsets.chunk_num = 0
    sd = mock.MagicMock()

    s._process_data(sd, mock.MagicMock(), offsets, mock.MagicMock())
    assert s._put_data.call_count == 1
    assert s._synccopy_bytes_sofar == 1
    assert sd.complete_offset_upload.call_count == 1


@mock.patch('blobxfer.operations.azure.blob.create_container')
@mock.patch('blobxfer.operations.azure.blob.append.create_blob')
@mock.patch('blobxfer.operations.azure.file.create_share')
@mock.patch('blobxfer.operations.azure.file.create_all_parent_directories')
@mock.patch('blobxfer.operations.azure.file.create_file')
@mock.patch('blobxfer.operations.azure.blob.page.create_blob')
def test_prepare_upload(page_cb, cf, capd, cs, append_cb, cc):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10

    ase.mode = azmodels.StorageModes.Append
    ase.append_create = True
    s._prepare_upload(ase)
    assert cc.call_count == 1
    assert append_cb.call_count == 1

    ase.mode = azmodels.StorageModes.Block
    ase.append_create = False
    s._prepare_upload(ase)
    assert cc.call_count == 2

    ase.mode = azmodels.StorageModes.File
    s._prepare_upload(ase)
    assert cs.call_count == 1
    assert capd.call_count == 1
    assert cf.call_count == 1

    ase.mode = azmodels.StorageModes.Page
    s._prepare_upload(ase)
    assert cc.call_count == 3
    assert page_cb.call_count == 1


@mock.patch('blobxfer.operations.azure.file.get_file_range')
@mock.patch('blobxfer.operations.azure.blob.get_blob_range')
def test_process_synccopy_descriptor(gbr, gfr):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10
    src_ase.is_encrypted = False

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Block
    dst_ase.size = 10
    dst_ase.is_encrypted = False

    sd = mock.MagicMock()
    sd.src_entity = src_ase
    sd.dst_entity = dst_ase
    sd.complete_offset_upload = mock.MagicMock()
    sd.next_offsets.return_value = (None, 1)
    sd.is_one_shot_block_blob = False
    sd.all_operations_completed = True

    s._finalize_upload = mock.MagicMock()
    s._transfer_set.add(
        ops.SyncCopy.create_unique_transfer_operation_id(src_ase, dst_ase))

    # test resume and completed
    s._process_synccopy_descriptor(sd)
    assert s._synccopy_bytes_sofar == 1
    assert s._finalize_upload.call_count == 1
    assert len(s._transfer_set) == 0
    assert s._synccopy_sofar == 1

    # test nothing
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    sd.all_operations_completed = False
    sd.next_offsets.return_value = (None, None)
    s._process_synccopy_descriptor(sd)
    assert s._transfer_queue.qsize() == 1

    # test normal block blob
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._prepare_upload = mock.MagicMock()
    s._process_data = mock.MagicMock()
    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10
    sd.next_offsets.return_value = (offsets, None)

    dst_ase.replica_targets = [dst_ase]

    s._process_synccopy_descriptor(sd)
    assert gbr.call_count == 1
    assert s._transfer_queue.qsize() == 1
    assert len(s._transfer_set) == 0

    # test normal append blob
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._prepare_upload = mock.MagicMock()
    s._process_data = mock.MagicMock()
    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10
    sd.next_offsets.return_value = (offsets, None)
    src_ase.mode = azmodels.StorageModes.Append

    s._process_synccopy_descriptor(sd)
    assert gbr.call_count == 2
    assert s._transfer_queue.qsize() == 1
    assert len(s._transfer_set) == 0

    # test normal file
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._prepare_upload = mock.MagicMock()
    s._process_data = mock.MagicMock()
    offsets = mock.MagicMock()
    offsets.chunk_num = 0
    offsets.num_bytes = 1
    offsets.range_start = 10
    sd.next_offsets.return_value = (offsets, None)
    src_ase.mode = azmodels.StorageModes.File

    s._process_synccopy_descriptor(sd)
    assert gfr.call_count == 1
    assert s._transfer_queue.qsize() == 1
    assert len(s._transfer_set) == 0


@mock.patch('blobxfer.operations.azure.blob.block.put_block_list')
def test_finalize_block_blob(pbl):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    sd = mock.MagicMock()
    sd.dst_entity = ase
    sd.last_block_num = 1

    s._finalize_block_blob(sd, mock.MagicMock(), mock.MagicMock())
    assert pbl.call_count == 2


@mock.patch('blobxfer.operations.azure.blob.set_blob_md5')
def test_set_blob_md5(sbm):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    sd = mock.MagicMock()
    sd.dst_entity = ase

    s._set_blob_md5(sd, mock.MagicMock())
    assert sbm.call_count == 2


@mock.patch('blobxfer.operations.azure.blob.set_blob_metadata')
def test_set_blob_metadata(sbm):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.is_encrypted = False
    ase.replica_targets = [ase]

    sd = mock.MagicMock()
    sd.dst_entity = ase

    s._set_blob_metadata(sd, mock.MagicMock())
    assert sbm.call_count == 2


def test_finalize_nonblock_blob():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    s._set_blob_md5 = mock.MagicMock()
    s._set_blob_metadata = mock.MagicMock()

    s._finalize_nonblock_blob(mock.MagicMock(), {'a': 0}, 'digest')
    assert s._set_blob_md5.call_count == 1
    assert s._set_blob_metadata.call_count == 1


@mock.patch('blobxfer.operations.azure.file.set_file_md5')
@mock.patch('blobxfer.operations.azure.file.set_file_metadata')
def test_finalize_azure_file(sfmeta, sfmd5):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.File
    ase.replica_targets = [ase]

    sd = mock.MagicMock()
    sd.dst_entity = ase

    s._finalize_azure_file(sd, {'a': 0}, 'md5')
    assert sfmd5.call_count == 2
    assert sfmeta.call_count == 2


def test_finalize_upload():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'asepath'
    ase.size = 10
    ase.mode = azmodels.StorageModes.Block
    ase.replica_targets = [ase]
    ase.md5 = 'md5'

    sd = mock.MagicMock()
    sd.dst_entity = ase
    sd.src_entity = ase

    s._finalize_block_blob = mock.MagicMock()
    s._finalize_upload(sd)
    assert s._finalize_block_blob.call_count == 1

    ase.md5 = None
    s._finalize_upload(sd)
    assert s._finalize_block_blob.call_count == 2

    sd.requires_put_block_list = False
    sd.remote_is_page_blob = True
    s._finalize_nonblock_blob = mock.MagicMock()
    s._finalize_upload(sd)
    assert s._finalize_nonblock_blob.call_count == 1

    sd.remote_is_page_blob = False
    sd.remote_is_append_blob = False
    sd.remote_is_file = True
    s._finalize_azure_file = mock.MagicMock()
    s._finalize_upload(sd)
    assert s._finalize_azure_file.call_count == 1


@mock.patch('blobxfer.models.metadata.get_md5_from_metadata')
def test_check_copy_conditions(gmfm):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Block
    dst_ase.size = 10
    dst_ase.from_local = False

    assert s._check_copy_conditions(src_ase, None) == ops.SynccopyAction.Copy

    s._spec.options.overwrite = False
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Skip

    s._spec.options.overwrite = True
    s._spec.skip_on.md5_match = True
    gmfm.return_value = 'md5'
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Skip

    gmfm.side_effect = ['md50', 'md51']
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Copy

    gmfm.return_value = None
    gmfm.side_effect = None
    s._spec.skip_on.md5_match = False
    s._spec.skip_on.filesize_match = False
    s._spec.skip_on.lmt_ge = False
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Copy

    # size mismatch
    s._spec.skip_on.filesize_match = True
    src_ase.size = 1
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Copy

    # size match
    s._spec.skip_on.filesize_match = True
    src_ase.size = dst_ase.size
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Skip

    # lmt match
    s._spec.skip_on.filesize_match = False
    s._spec.skip_on.lmt_ge = True
    src_ase.lmt = 0
    dst_ase.lmt = 0
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Skip

    # lmt mismatch
    s._spec.skip_on.lmt_ge = True
    src_ase.lmt = 1
    assert s._check_copy_conditions(
        src_ase, dst_ase) == ops.SynccopyAction.Copy


@mock.patch('blobxfer.operations.azure.file.get_file_properties')
@mock.patch('blobxfer.operations.azure.blob.get_blob_properties')
def test_check_for_existing_remote(gbp, gfp):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'

    s._spec.options.dest_mode = azmodels.StorageModes.File
    gfp.return_value = None
    assert s._check_for_existing_remote(sa, 'cont', 'name') is None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=False):
        gfp.return_value = mock.MagicMock()
        assert s._check_for_existing_remote(sa, 'cont', 'name') is not None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=True):
        with mock.patch(
                'blobxfer.models.crypto.EncryptionMetadata.convert_from_json'):
            gfp.return_value = mock.MagicMock()
            assert s._check_for_existing_remote(sa, 'cont', 'name') is not None

    s._spec.options.dest_mode = azmodels.StorageModes.Block
    gbp.return_value = None
    assert s._check_for_existing_remote(sa, 'cont', 'name') is None

    with mock.patch(
            'blobxfer.models.crypto.EncryptionMetadata.'
            'encryption_metadata_exists', return_value=False):
        gbp.return_value = mock.MagicMock()
        assert s._check_for_existing_remote(sa, 'cont', 'name') is not None


def test_get_destination_paths():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    paths = mock.MagicMock()
    paths.paths = [pathlib.Path('a/b')]
    s._spec.destinations = [paths]

    sa, cont, dir, dpath = next(s._get_destination_paths())
    assert cont == 'a'
    assert dir == 'b'
    assert dpath == pathlib.Path('a/b')


def test_generate_destination_for_source():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._spec.options.dest_mode = azmodels.StorageModes.Block
    s._spec.options.rename = False
    s._check_for_existing_remote = mock.MagicMock()
    s._check_for_existing_remote.return_value = None

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10
    src_ase.name = 'srcase'

    sa = mock.MagicMock()
    sa.name = 'name'
    sa.endpoint = 'ep'

    s._get_destination_paths = mock.MagicMock()
    s._get_destination_paths.return_value = [
        (sa, 'cont', 'dstname', 'dpath'),
    ]

    s._check_copy_conditions = mock.MagicMock()
    s._check_copy_conditions.return_value = ops.SynccopyAction.Copy

    ase = next(s._generate_destination_for_source(src_ase))
    assert ase is not None
    assert ase.size == src_ase.size
    assert ase.mode == s._spec.options.dest_mode
    assert pathlib.Path(ase.name) == pathlib.Path('dstname', src_ase.name)

    s._get_destination_paths.return_value = [
        (sa, 'cont', 'name', 'dpath'),
    ]
    s._spec.options.rename = True
    ase = next(s._generate_destination_for_source(src_ase))
    assert ase.name == 'name'

    s._get_destination_paths.return_value = [
        (sa, 'cont', '', 'dpath'),
    ]
    s._spec.options.rename = True
    with pytest.raises(RuntimeError):
        next(s._generate_destination_for_source(src_ase))


def test_bind_sources_to_destination():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._spec.options.delete_extraneous_destination = True

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.container = 'srccont'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10
    src_ase.name = 'srcase'

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.container = 'dstcont'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Block
    dst_ase.size = 10
    dst_ase.name = 'dstase'
    dst_ase.from_local = False
    dst_ase.replica_targets = None

    dst2_ase = mock.MagicMock()
    dst2_ase._client.primary_endpoint = 'ep2a'
    dst2_ase.container = 'dstcont2'
    dst2_ase.name = 'dstase2'

    src = mock.MagicMock()
    src.files.return_value = [src_ase]

    s._spec.sources = [src]

    s._generate_destination_for_source = mock.MagicMock()
    i = 0
    for a, b in s._bind_sources_to_destination():
        i += 1
    assert i == 0

    s._generate_destination_for_source.return_value = [dst_ase, dst2_ase]
    a, b = next(s._bind_sources_to_destination())
    assert a == src_ase
    assert b == dst_ase
    assert len(b.replica_targets) == 1
    assert b.replica_targets[0] == dst2_ase

    dst_ase.replica_targets = [dst2_ase]
    s._generate_destination_for_source.return_value = [dst_ase, dst2_ase]
    with pytest.raises(RuntimeError):
        a, b = next(s._bind_sources_to_destination())

    dst_ase.replica_targets = None
    s._spec.options.delete_extraneous_destination = False
    src.files.return_value = [src_ase, src_ase]
    s._generate_destination_for_source.return_value = [dst_ase]
    with pytest.raises(RuntimeError):
        for a, b in s._bind_sources_to_destination():
            pass


@mock.patch('blobxfer.operations.azure.file.get_file_range')
@mock.patch('blobxfer.operations.azure.blob.get_blob_range')
@mock.patch('blobxfer.operations.resume.SyncCopyResumeManager')
def test_run(srm, gbr, gfr):
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._general_options.concurrency.transfer_threads = 1
    s._general_options.resume_file = 'resume'
    s._spec.options.chunk_size_bytes = 0

    src_ase = mock.MagicMock()
    src_ase._client.primary_endpoint = 'ep'
    src_ase.container = 'srccont'
    src_ase.path = 'srcasepath'
    src_ase.mode = azmodels.StorageModes.Block
    src_ase.size = 10
    src_ase.name = 'srcase'

    dst_ase = mock.MagicMock()
    dst_ase._client.primary_endpoint = 'ep2'
    dst_ase.container = 'dstcont'
    dst_ase.path = 'dstasepath'
    dst_ase.mode = azmodels.StorageModes.Block
    dst_ase.size = 10
    dst_ase.name = 'dstase'
    dst_ase.from_local = False
    dst_ase.replica_targets = None

    s._bind_sources_to_destination = mock.MagicMock()
    s._bind_sources_to_destination.return_value = [
        (src_ase, dst_ase)
    ]

    s._prepare_upload = mock.MagicMock()
    s._put_data = mock.MagicMock()
    s._finalize_upload = mock.MagicMock()

    # normal execution
    s._synccopy_start_time = (
        util.datetime_now() - datetime.timedelta(seconds=1)
    )
    s._run()
    assert s._prepare_upload.call_count == 1
    assert s._put_data.call_count == 1

    # replica targets with mismatch
    s._synccopy_start_time = None
    dst_ase.replica_targets = [dst_ase]
    with pytest.raises(RuntimeError):
        s._run()

    # exception during worker thread
    dst_ase.replica_targets = None
    with pytest.raises(RuntimeError):
        s._process_synccopy_descriptor = mock.MagicMock()
        s._process_synccopy_descriptor.side_effect = RuntimeError()
        s._run()


def test_start():
    s = ops.SyncCopy(mock.MagicMock(), mock.MagicMock(), mock.MagicMock())
    s._wait_for_transfer_threads = mock.MagicMock()
    s._resume = mock.MagicMock()
    s._run = mock.MagicMock()

    # test keyboard interrupt
    s._run.side_effect = KeyboardInterrupt()
    s.start()

    assert s._run.call_count == 1
    assert s._wait_for_transfer_threads.call_count == 1
    assert s._resume.close.call_count == 1

    # test other exception
    s._run.side_effect = RuntimeError()
    with pytest.raises(RuntimeError):
        s.start()
