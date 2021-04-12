# coding=utf-8
"""Tests for models synccopy"""

# stdlib imports
import unittest.mock as mock
# non-stdlib imports
import bitstring
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.options as options
# module under test
import blobxfer.models.synccopy as synccopy


def test_specification():
    spec = synccopy.Specification(
        synccopy_options=options.SyncCopy(
            access_tier=None,
            delete_extraneous_destination=False,
            delete_only=False,
            dest_mode=azmodels.StorageModes.Auto,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=False,
            server_side_copy=True,
            strip_components=0,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        )
    )

    spec.add_azure_source_path(mock.MagicMock())
    assert len(spec.sources) == 1

    spec.add_azure_destination_path(mock.MagicMock())
    assert len(spec.destinations) == 1


def test_descriptor():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto
    opts.server_side_copy = False

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None
    src_ase._is_arbitrary_url = False

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert d._offset == 0
    assert d._chunk_num == 0
    assert not d._finalized
    assert d._src_block_list is None

    assert d.src_entity == src_ase
    assert d.dst_entity == dst_ase
    assert not d.all_operations_completed
    assert d.is_resumable
    assert d.last_block_num == -1
    assert not d.remote_is_file
    assert not d.remote_is_page_blob
    assert not d.remote_is_append_blob
    assert d.is_one_shot_block_blob
    assert not d.requires_put_block_list

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Page
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = None

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert not d.is_one_shot_block_blob
    assert not d.requires_put_block_list

    opts.server_side_copy = True
    dst_ase._mode = azmodels.StorageModes.Page
    with pytest.raises(ValueError):
        d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 0
    dst_ase._encryption = None
    dst_ase.replica_targets = None

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert d.is_one_shot_block_blob
    assert not d.requires_put_block_list

    dst_ase._size = 32

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert not d.is_one_shot_block_blob
    assert d.requires_put_block_list


def test_descriptor_complete_offset_upload():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    d.complete_offset_upload(0)
    assert d._outstanding_ops == 1

    d.complete_offset_upload(0)
    assert d._outstanding_ops == 0
    assert 0 not in d._replica_counters


def test_descriptor_compute_chunk_size():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto
    opts.server_side_copy = False

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None
    src_ase._is_arbitrary_url = False

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert d._compute_chunk_size() == \
        synccopy._DEFAULT_AUTO_CHUNKSIZE_BYTES

    dst_ase._mode = azmodels.StorageModes.Page
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert d._compute_chunk_size() == \
        synccopy._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES

    dst_ase._mode = azmodels.StorageModes.Block
    d = synccopy.Descriptor(src_ase, dst_ase, [], opts, mock.MagicMock())
    assert d._compute_chunk_size() == d.src_entity.size

    b = mock.MagicMock()
    b.size = 1
    d = synccopy.Descriptor(src_ase, dst_ase, [b], opts, mock.MagicMock())
    assert d._compute_chunk_size() == 1

    d = synccopy.Descriptor(src_ase, dst_ase, [b, b], opts, mock.MagicMock())
    assert d._compute_chunk_size() == -1


def test_descriptor_compute_total_chunks():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, mock.MagicMock())
    assert d._compute_total_chunks(0) == 1


def test_resume():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    # test no resume
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, None)
    assert d._resume() is None

    # check if path exists in resume db
    resume = mock.MagicMock()
    resume.get_record.return_value = None
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, resume)
    assert d._resume() is None

    # check same lengths
    bad = mock.MagicMock()
    bad.length = 0
    resume.get_record.return_value = bad
    assert d._resume() is None

    # check completed resume
    comp = mock.MagicMock()
    comp.length = 32
    comp.completed = True
    comp.total_chunks = 1
    comp.chunk_size = 32
    comp.completed_chunks = 1
    resume.get_record.return_value = comp
    dst_ase.replica_targets = None
    d._completed_chunks = mock.MagicMock()
    assert d._resume() == 32

    dst_ase.replica_targets = [dst_ase]
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, resume)
    d._completed_chunks = mock.MagicMock()
    assert d._resume() == 64

    # check resume no md5
    nc = mock.MagicMock()
    nc.offset = 16
    nc.length = 32
    nc.completed = False
    nc.total_chunks = 2
    nc.chunk_size = 16
    cc = bitstring.BitArray(length=nc.total_chunks)
    cc.set(True, 0)
    nc.completed_chunks = cc.int

    resume.get_record.return_value = nc
    dst_ase.replica_targets = None
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, resume)
    assert d._resume() == 16


def test_descriptor_next_offsets():
    opts = mock.MagicMock()
    opts.dest_mode = azmodels.StorageModes.Auto
    opts.mode = azmodels.StorageModes.Auto

    src_ase = azmodels.StorageEntity('cont')
    src_ase._mode = azmodels.StorageModes.Block
    src_ase._name = 'name'
    src_ase._size = 32
    src_ase._encryption = None

    dst_ase = azmodels.StorageEntity('cont2')
    dst_ase._mode = azmodels.StorageModes.Block
    dst_ase._name = 'name'
    dst_ase._size = 32
    dst_ase._encryption = None
    dst_ase.replica_targets = [mock.MagicMock()]

    # test normal
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, None)
    d._resume = mock.MagicMock()
    d._resume.return_value = None

    offsets, rb = d.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 32
    assert offsets.range_start == 0
    assert offsets.range_end == 31
    assert d._offset == 32
    assert d._chunk_num == 1

    # test nothing left
    offsets, rb = d.next_offsets()
    assert rb is None
    assert offsets is None

    # test neg chunk size with block list
    b = mock.MagicMock()
    b.size = 10
    d = synccopy.Descriptor(src_ase, dst_ase, [b], opts, None)
    d._resume = mock.MagicMock()
    d._resume.return_value = None
    d._chunk_size = -1

    offsets, rb = d.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 10
    assert offsets.range_start == 0
    assert offsets.range_end == 9
    assert d._offset == 10
    assert d._chunk_num == 1

    # test small chunk size
    d = synccopy.Descriptor(src_ase, dst_ase, None, opts, None)
    d._resume = mock.MagicMock()
    d._resume.return_value = None
    d._chunk_size = 32
    offsets, rb = d.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 32
    assert offsets.range_start == 0
    assert offsets.range_end == 31
    assert d._offset == 32
    assert d._chunk_num == 1
