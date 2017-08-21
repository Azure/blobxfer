# coding=utf-8
"""Tests for models resume"""

# stdlib imports
# non-stdlib imports
# module under test
import blobxfer.models.resume as rmodels


def test_download():
    d = rmodels.Download('fp', 1, 2, 0, False, '')
    assert d.final_path == 'fp'
    assert d.length == 1
    assert d.chunk_size == 2
    assert d.next_integrity_chunk == 0
    assert not d.completed
    assert d.md5hexdigest == ''

    d.md5hexdigest = None
    assert d.md5hexdigest == ''

    d.md5hexdigest = 'abc'
    assert d.md5hexdigest == 'abc'

    d.next_integrity_chunk = 1
    assert d.next_integrity_chunk == 1

    d.completed = True
    assert d.completed

    assert len(str(d)) > 0


def test_upload():
    u = rmodels.Upload('lp', 1, 2, 2, 0, False, '')
    assert u.local_path == 'lp'
    assert u.length == 1
    assert u.chunk_size == 2
    assert u.total_chunks == 2
    assert u.completed_chunks == 0
    assert not u.completed
    assert u.md5hexdigest == ''

    u.md5hexdigest = None
    assert u.md5hexdigest == ''

    u.md5hexdigest = 'abc'
    assert u.md5hexdigest == 'abc'

    u.completed_chunks = 1
    assert u.completed_chunks == 1

    u.completed = True
    assert u.completed

    assert len(str(u)) > 0


def test_synccopy():
    s = rmodels.SyncCopy(1, [], 0, 2, 2, 0, False)
    assert s.length == 1
    assert len(s.src_block_list) == 0
    assert s.offset == 0
    assert s.chunk_size == 2
    assert s.total_chunks == 2
    assert s.completed_chunks == 0
    assert not s.completed

    s.offset = 1
    assert s.offset == 1

    s.completed_chunks = 1
    assert s.completed_chunks == 1

    s.completed = True
    assert s.completed

    assert len(str(s)) > 0
