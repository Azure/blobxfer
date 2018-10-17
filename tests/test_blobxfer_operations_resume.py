# coding=utf-8
"""Tests for operations resume"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
# local imports
# module under test
import blobxfer.operations.resume as ops


def test_generate_record_key():
    ase = mock.MagicMock()
    ase._client.primary_endpoint = 'ep'
    ase.path = 'abc'

    with mock.patch('blobxfer.util.on_python2', return_value=True):
        assert ops._BaseResumeManager.generate_record_key(ase) == b'ep:abc'

    with mock.patch('blobxfer.util.on_python2', return_value=False):
        assert ops._BaseResumeManager.generate_record_key(ase) == 'ep:abc'


def test_download_resume_manager(tmpdir):
    tmpdb = pathlib.Path(str(tmpdir.join('tmp.db')))
    tmpdb_dat = pathlib.Path(str(tmpdir.join('tmp.db.dat')))

    drm = ops.DownloadResumeManager(tmpdb)

    assert drm._data is not None
    drm.close()
    assert drm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()
    drm.delete()
    assert drm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()

    ase = mock.MagicMock()
    ase._name = 'name'
    ase._client.primary_endpoint = 'ep'
    ase._size = 16

    final_path = 'fp'
    drm = ops.DownloadResumeManager(tmpdb)
    drm.add_or_update_record(final_path, ase, 2, 0, False, None)
    d = drm.get_record(ase)

    assert d.final_path == final_path

    drm.add_or_update_record(final_path, ase, 2, 1, False, 'abc')
    d = drm.get_record(ase)

    assert d.final_path == final_path
    assert not d.completed
    assert d.next_integrity_chunk == 1
    assert d.md5hexdigest == 'abc'

    drm.add_or_update_record(final_path, ase, 2, 1, True, None)
    d = drm.get_record(ase)

    assert d.final_path == final_path
    assert d.completed
    assert d.next_integrity_chunk == 1
    assert d.md5hexdigest == 'abc'

    # idempotent check after completed
    drm.add_or_update_record(final_path, ase, 2, 1, True, None)
    d = drm.get_record(ase)

    assert d.final_path == final_path
    assert d.completed
    assert d.next_integrity_chunk == 1
    assert d.md5hexdigest == 'abc'

    drm.close()
    assert drm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()

    drm.delete()
    assert drm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()

    # oserror path
    with mock.patch('blobxfer.util.on_windows', return_value=False):
        drm.delete()
    assert drm._data is None

    # oserror path
    with mock.patch('blobxfer.util.on_windows', return_value=True):
        with mock.patch('blobxfer.util.on_python2', return_value=False):
            drm.delete()
    assert drm._data is None

    # oserror path
    with mock.patch('blobxfer.util.on_python2', return_value=True):
        drm.delete()
    assert drm._data is None


def test_upload_resume_manager(tmpdir):
    tmpdb = pathlib.Path(str(tmpdir.join('tmp.db')))
    tmpdb_dat = pathlib.Path(str(tmpdir.join('tmp.db.dat')))

    urm = ops.UploadResumeManager(tmpdb)
    assert urm._data is not None
    urm.close()
    assert urm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()
    urm.delete()
    assert urm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()

    ase = mock.MagicMock()
    ase._name = 'name'
    ase._client.primary_endpoint = 'ep'
    ase._size = 16

    local_path = 'fp'
    urm = ops.UploadResumeManager(tmpdb)
    urm.add_or_update_record(local_path, ase, 2, 8, 0, False, None)
    u = urm.get_record(ase)

    assert u.local_path == local_path
    assert u.length == ase._size
    assert u.chunk_size == 2
    assert u.total_chunks == 8
    assert u.completed_chunks == 0
    assert not u.completed

    urm.add_or_update_record(local_path, ase, 2, 8, 1, False, 'abc')
    u = urm.get_record(ase)

    assert u.local_path == local_path
    assert u.length == ase._size
    assert u.chunk_size == 2
    assert u.total_chunks == 8
    assert u.completed_chunks == 1
    assert not u.completed
    assert u.md5hexdigest == 'abc'

    urm.add_or_update_record(local_path, ase, 2, 8, 8, True, None)
    u = urm.get_record(ase)

    assert u.local_path == local_path
    assert u.length == ase._size
    assert u.chunk_size == 2
    assert u.total_chunks == 8
    assert u.completed_chunks == 8
    assert u.completed
    assert u.md5hexdigest == 'abc'

    # idempotent check after completed
    urm.add_or_update_record(local_path, ase, 2, 8, 8, True, None)
    u = urm.get_record(ase)

    assert u.local_path == local_path
    assert u.length == ase._size
    assert u.chunk_size == 2
    assert u.total_chunks == 8
    assert u.completed_chunks == 8
    assert u.completed
    assert u.md5hexdigest == 'abc'

    urm.close()
    assert urm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()

    urm.delete()
    assert urm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()


def test_synccopy_resume_manager(tmpdir):
    tmpdb = pathlib.Path(str(tmpdir.join('tmp.db')))
    tmpdb_dat = pathlib.Path(str(tmpdir.join('tmp.db.dat')))

    srm = ops.SyncCopyResumeManager(tmpdb)
    assert srm._data is not None
    srm.close()
    assert srm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()
    srm.delete()
    assert srm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()

    ase = mock.MagicMock()
    ase._name = 'name'
    ase._client.primary_endpoint = 'ep'
    ase._size = 16

    src_block_list = 'srcbl'

    srm = ops.SyncCopyResumeManager(tmpdb)
    srm.add_or_update_record(ase, src_block_list, 0, 2, 8, 0, False)
    s = srm.get_record(ase)

    assert s.src_block_list == src_block_list
    assert s.length == ase._size
    assert s.offset == 0
    assert s.chunk_size == 2
    assert s.total_chunks == 8
    assert s.completed_chunks == 0
    assert not s.completed

    srm.add_or_update_record(ase, src_block_list, 1, 2, 8, 1, False)
    s = srm.get_record(ase)

    assert s.src_block_list == src_block_list
    assert s.length == ase._size
    assert s.offset == 1
    assert s.chunk_size == 2
    assert s.total_chunks == 8
    assert s.completed_chunks == 1
    assert not s.completed

    srm.add_or_update_record(ase, src_block_list, 8, 2, 8, 8, True)
    s = srm.get_record(ase)

    assert s.src_block_list == src_block_list
    assert s.length == ase._size
    assert s.offset == 8
    assert s.chunk_size == 2
    assert s.total_chunks == 8
    assert s.completed_chunks == 8
    assert s.completed

    # idempotent check after completed
    srm.add_or_update_record(ase, src_block_list, 8, 2, 8, 8, True)
    s = srm.get_record(ase)

    assert s.src_block_list == src_block_list
    assert s.length == ase._size
    assert s.offset == 8
    assert s.chunk_size == 2
    assert s.total_chunks == 8
    assert s.completed_chunks == 8
    assert s.completed

    srm.close()
    assert srm._data is None
    assert tmpdb_dat.exists() or tmpdb.exists()

    srm.delete()
    assert srm._data is None
    assert not tmpdb_dat.exists() and not tmpdb.exists()
