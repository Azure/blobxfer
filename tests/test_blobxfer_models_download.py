# coding=utf-8
"""Tests for download models"""

# stdlib imports
import hashlib
import hmac
import mock
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.options as options
import blobxfer.operations.azure as azops
import blobxfer.util as util
# module under test
import blobxfer.models.download as models


def test_localdestinationpath(tmpdir):
    tmpdir.mkdir('1')
    path = tmpdir.join('1')

    a = models.LocalDestinationPath(str(path))
    a.is_dir = True
    assert str(a.path) == str(path)
    assert a.is_dir

    a.ensure_path_exists()
    assert os.path.exists(str(a.path))

    b = models.LocalDestinationPath()
    b.is_dir = False
    b.path = str(path)
    with pytest.raises(RuntimeError):
        b.ensure_path_exists()
    assert not b.is_dir

    path2 = tmpdir.join('2')
    path3 = path2.join('3')
    c = models.LocalDestinationPath(str(path3))
    with pytest.raises(RuntimeError):
        c.ensure_path_exists()
    c.is_dir = False
    c.ensure_path_exists()
    assert os.path.exists(str(path2))
    assert os.path.isdir(str(path2))
    assert not c.is_dir


def test_downloadspecification():
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
            md5_match=True,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )

    asp = azops.SourcePath()
    p = 'some/remote/path'
    asp.add_path_with_storage_account(p, 'sa')

    ds.add_azure_source_path(asp)

    assert ds.options.check_file_md5
    assert not ds.skip_on.lmt_ge
    assert ds.destination.path == pathlib.Path('dest')
    assert len(ds.sources) == 1
    assert p in ds.sources[0]._path_map
    assert ds.sources[0]._path_map[p] == 'sa'


def test_downloaddescriptor(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 1024
    ase._encryption = mock.MagicMock()
    with pytest.raises(RuntimeError):
        d = models.Descriptor(lp, ase, opts, None)

    ase._encryption.symmetric_key = b'123'
    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()

    assert d.entity == ase
    assert not d.must_compute_md5
    assert d._total_chunks == 64
    assert d._offset == 0
    assert d.final_path == lp
    assert str(d.local_path) == str(lp) + '.bxtmp'
    assert d._allocated
    assert d.local_path.stat().st_size == 1024 - 16

    d.local_path.unlink()
    ase._size = 1
    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    assert d._total_chunks == 1
    assert d._allocated
    assert d.local_path.stat().st_size == 0

    d.local_path.unlink()
    ase._encryption = None
    ase._size = 1024
    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    assert d._allocated
    assert d.local_path.stat().st_size == 1024

    # pre-existing file check
    ase._size = 0
    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    assert d._total_chunks == 0
    assert d._allocated
    assert d.local_path.stat().st_size == 0


def test_downloaddescriptor_next_offsets(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 256
    ase = azmodels.StorageEntity('cont')
    ase._size = 128
    d = models.Descriptor(lp, ase, opts, None)

    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 1
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 128
    assert offsets.range_start == 0
    assert offsets.range_end == 127
    assert not offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._size = 0
    d = models.Descriptor(lp, ase, opts, None)
    assert d._total_chunks == 0
    assert d.next_offsets() == (None, None)

    ase._size = 1
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 1
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 1
    assert offsets.range_start == 0
    assert offsets.range_end == 0
    assert not offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._size = 256
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 1
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._size = 256 + 16
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 2
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert offsets.chunk_num == 1
    assert offsets.fd_start == 256
    assert offsets.num_bytes == 16
    assert offsets.range_start == 256
    assert offsets.range_end == 256 + 15
    assert not offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = b'123'
    ase._size = 128
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 1
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 128
    assert offsets.range_start == 0
    assert offsets.range_end == 127
    assert offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._size = 256
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 1
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert offsets.unpad
    assert d.next_offsets() == (None, None)

    ase._size = 256 + 32  # 16 bytes over + padding
    d = models.Descriptor(lp, ase, opts, None)
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert d._total_chunks == 2
    assert offsets.chunk_num == 0
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    offsets, resume_bytes = d.next_offsets()
    assert resume_bytes is None
    assert offsets.chunk_num == 1
    assert offsets.fd_start == 256
    assert offsets.num_bytes == 32
    assert offsets.range_start == 256 - 16
    assert offsets.range_end == 256 + 31
    assert offsets.unpad
    assert d.next_offsets() == (None, None)


def test_write_unchecked_data(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 32
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    d.write_unchecked_data(offsets, b'0' * ase._size)

    assert offsets.chunk_num in d._unchecked_chunks
    ucc = d._unchecked_chunks[offsets.chunk_num]
    assert ucc.data_len == ase._size
    assert ucc.fd_start == offsets.fd_start
    assert ucc.file_path == d.local_path
    assert not ucc.temp


def test_write_unchecked_hmac_data(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 32
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    d.write_unchecked_hmac_data(offsets, b'0' * ase._size)

    assert offsets.chunk_num in d._unchecked_chunks
    ucc = d._unchecked_chunks[offsets.chunk_num]
    assert ucc.data_len == ase._size
    assert ucc.fd_start == offsets.fd_start
    assert ucc.file_path != d.local_path
    assert ucc.temp


def test_perform_chunked_integrity_check(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    data = b'0' * opts.chunk_size_bytes
    d.write_unchecked_data(offsets, data)
    d.perform_chunked_integrity_check()

    assert d._next_integrity_chunk == 1
    assert 0 not in d._unchecked_chunks
    assert len(d._unchecked_chunks) == 0

    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = b'123'
    d = models.Descriptor(lp, ase, opts, None)

    data = b'0' * opts.chunk_size_bytes
    offsets, _ = d.next_offsets()
    d.write_unchecked_hmac_data(offsets, data)
    ucc = d._unchecked_chunks[offsets.chunk_num]
    offsets1, _ = d.next_offsets()
    d.write_unchecked_hmac_data(offsets1, data)
    ucc1 = d._unchecked_chunks[offsets1.chunk_num]
    d.perform_chunked_integrity_check()

    assert not ucc.file_path.exists()
    assert not ucc1.file_path.exists()
    assert d._next_integrity_chunk == 2
    assert 0 not in d._unchecked_chunks
    assert 1 not in d._unchecked_chunks
    assert len(d._unchecked_chunks) == 0


def test_cleanup_all_temporary_files(tmpdir):
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 16
    lp = pathlib.Path(str(tmpdir.join('a')))
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    data = b'0' * opts.chunk_size_bytes
    d.write_unchecked_data(offsets, data)
    assert len(d._unchecked_chunks) == 1
    d.cleanup_all_temporary_files()
    assert not d.local_path.exists()
    assert not d._unchecked_chunks[0].file_path.exists()

    lp = pathlib.Path(str(tmpdir.join('b')))
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    data = b'0' * opts.chunk_size_bytes
    d.write_unchecked_hmac_data(offsets, data)
    assert len(d._unchecked_chunks) == 1
    d.local_path.unlink()
    d._unchecked_chunks[0].file_path.unlink()
    d.cleanup_all_temporary_files()
    assert not d.local_path.exists()
    assert not d._unchecked_chunks[0].file_path.exists()


def test_write_data(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    d = models.Descriptor(lp, ase, opts, None)

    offsets, _ = d.next_offsets()
    data = b'0' * ase._size
    d.write_data(offsets, data)

    assert d.local_path.exists()
    assert d.local_path.stat().st_size == len(data)


def test_finalize_file(tmpdir):
    # hmac check success
    lp = pathlib.Path(str(tmpdir.join('a')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32
    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = b'123'
    signkey = os.urandom(32)
    ase._encryption.initialize_hmac = mock.MagicMock()
    ase._encryption.initialize_hmac.return_value = hmac.new(
        signkey, digestmod=hashlib.sha256)

    data = b'0' * (ase._size - 16)
    _hmac = hmac.new(signkey, digestmod=hashlib.sha256)
    _hmac.update(data)
    ase._encryption.encryption_authentication.\
        message_authentication_code = util.base64_encode_as_string(
            _hmac.digest())

    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    d.hmac.update(data)
    d.finalize_file()

    assert not d.local_path.exists()
    assert d.final_path.exists()
    assert d.final_path.stat().st_size == len(data)

    # md5 check success
    lp = pathlib.Path(str(tmpdir.join('b')))
    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32

    data = b'0' * ase._size
    md5 = util.new_md5_hasher()
    md5.update(data)
    ase._md5 = util.base64_encode_as_string(md5.digest())

    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    d.md5.update(data)
    d.finalize_file()

    assert not d.local_path.exists()
    assert d.final_path.exists()
    assert d.final_path.stat().st_size == len(data)

    # no check
    lp = pathlib.Path(str(tmpdir.join('c')))
    opts = mock.MagicMock()
    opts.check_file_md5 = False
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32

    data = b'0' * ase._size

    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    d.finalize_file()

    assert not d.local_path.exists()
    assert d.final_path.exists()
    assert d.final_path.stat().st_size == len(data)

    # md5 mismatch
    lp = pathlib.Path(str(tmpdir.join('d')))
    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32

    data = b'0' * ase._size
    ase._md5 = 'oops'

    d = models.Descriptor(lp, ase, opts, None)
    d._allocate_disk_space()
    d.md5.update(data)
    d.finalize_file()

    assert not d.local_path.exists()
    assert not d.final_path.exists()


def test_operations(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))
    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = azmodels.StorageEntity('cont')
    ase._size = 32

    d = models.Descriptor(lp, ase, opts, None)
    d._outstanding_ops = 1
    d._unchecked_chunks = {0: None}
    assert not d.all_operations_completed

    d._outstanding_ops -= 1
    d._unchecked_chunks.pop(0)
    assert d.all_operations_completed
