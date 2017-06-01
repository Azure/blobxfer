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
# module under test
import blobxfer.operations.resume as ops


def test_download_resume_manager(tmpdir):
    tmpdb = pathlib.Path(str(tmpdir.join('tmp.db')))

    drm = ops.DownloadResumeManager(tmpdb)
    assert drm._data is not None
    drm.close()
    assert drm._data is None
    assert tmpdb.exists()
    drm.delete()
    assert drm._data is None
    assert not tmpdb.exists()

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
    assert tmpdb.exists()

    tmpdb.unlink()
    drm.delete()
    assert drm._data is None
    assert not tmpdb.exists()
