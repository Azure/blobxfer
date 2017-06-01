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
