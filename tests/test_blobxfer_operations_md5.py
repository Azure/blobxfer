# coding=utf-8
"""Tests for md5"""

# stdlib imports
import time
import uuid
# non-stdlib imports
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.upload as modelsul
# module under test
import blobxfer.operations.md5 as ops


def test_compute_md5(tmpdir):
    lpath = str(tmpdir.join('test.tmp'))
    testdata = str(uuid.uuid4())
    with open(lpath, 'wt') as f:
        f.write(testdata)
    md5_file = ops.compute_md5_for_file_asbase64(lpath)
    md5_data = ops.compute_md5_for_data_asbase64(testdata.encode('utf8'))
    assert md5_file == md5_data

    # test offset
    md5_file = ops.compute_md5_for_file_asbase64(lpath, start=1)
    md5_data = ops.compute_md5_for_data_asbase64(testdata[1:].encode('utf8'))
    assert md5_file == md5_data

    md5_file = ops.compute_md5_for_file_asbase64(lpath, end=2)
    md5_data = ops.compute_md5_for_data_asbase64(testdata[:2].encode('utf8'))
    assert md5_file == md5_data

    # test mismatch
    md5_file_page = ops.compute_md5_for_file_asbase64(lpath, True)
    assert md5_file != md5_file_page

    # test non-existent file
    with pytest.raises(IOError):
        ops.compute_md5_for_file_asbase64(testdata)


def test_check_data_is_empty():
    data = b'\0' * ops._MAX_PAGE_SIZE_BYTES
    assert ops.check_data_is_empty(data)

    data = b'\0' * 8
    assert ops.check_data_is_empty(data)

    data = str(uuid.uuid4()).encode('utf8')
    assert not ops.check_data_is_empty(data)


def test_done_cv():
    a = None
    try:
        a = ops.LocalFileMd5Offload(num_workers=1)
        assert a.done_cv == a._done_cv
    finally:
        if a:
            a.finalize_processes()


def test_finalize_md5_processes():
    with pytest.raises(ValueError):
        ops.LocalFileMd5Offload(num_workers=0)

    a = None
    try:
        a = ops.LocalFileMd5Offload(num_workers=1)
    finally:
        if a:
            a.finalize_processes()

    for proc in a._procs:
        assert not proc.is_alive()


def test_from_add_to_done_non_pagealigned(tmpdir):
    file = tmpdir.join('a')
    file.write('abc')
    fpath = str(file)
    key = 'key'

    remote_md5 = ops.compute_md5_for_file_asbase64(str(file))

    a = None
    try:
        a = ops.LocalFileMd5Offload(num_workers=1)
        result = a.pop_done_queue()
        assert result is None

        with pytest.raises(ValueError):
            a.add_localfile_for_md5_check(None, None, None, None, None, None)

        a.add_localfile_for_md5_check(
            key, fpath, fpath, remote_md5, azmodels.StorageModes.Block, None)
        i = 33
        checked = False
        while i > 0:
            result = a.pop_done_queue()
            if result is None:
                time.sleep(0.3)
                i -= 1
                continue
            assert len(result) == 5
            assert result[0] == key
            assert result[1] == str(file)
            assert result[2] is None
            assert result[3] == remote_md5
            assert result[4]
            checked = True
            break
        assert checked
    finally:
        if a:
            a.finalize_processes()


def test_from_add_to_done_lpview(tmpdir):
    file = tmpdir.join('a')
    file.write('abc')
    fpath = str(file)
    key = 'key'

    remote_md5 = ops.compute_md5_for_file_asbase64(str(file))

    a = None
    lpview = modelsul.LocalPathView(
        fd_start=0,
        fd_end=3,
        mode=None,
        next=None,
        slice_num=None,
        total_slices=1,
    )
    try:
        a = ops.LocalFileMd5Offload(num_workers=1)
        result = a.pop_done_queue()
        assert result is None

        a.add_localfile_for_md5_check(
            key, fpath, fpath, remote_md5, azmodels.StorageModes.Block, lpview)
        i = 33
        checked = False
        while i > 0:
            result = a.pop_done_queue()
            if result is None:
                time.sleep(0.3)
                i -= 1
                continue
            assert len(result) == 5
            assert result[0] == key
            assert result[1] == str(file)
            assert result[2] == 3
            assert result[3] == remote_md5
            assert result[4]
            checked = True
            break
        assert checked
    finally:
        if a:
            a.finalize_processes()


def test_from_add_to_done_pagealigned(tmpdir):
    file = tmpdir.join('a')
    file.write('abc')
    fpath = str(file)
    key = 'key'

    remote_md5 = ops.compute_md5_for_file_asbase64(str(file), True)

    a = None
    try:
        a = ops.LocalFileMd5Offload(num_workers=1)
        result = a.pop_done_queue()
        assert result is None

        a.add_localfile_for_md5_check(
            key, fpath, fpath, remote_md5, azmodels.StorageModes.Page, None)
        i = 33
        checked = False
        while i > 0:
            result = a.pop_done_queue()
            if result is None:
                time.sleep(0.3)
                i -= 1
                continue
            assert len(result) == 5
            assert result[0] == key
            assert result[1] == str(file)
            assert result[2] is None
            assert result[3] == remote_md5
            assert result[4]
            checked = True
            break
        assert checked
    finally:
        if a:
            a.finalize_processes()
