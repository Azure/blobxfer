# coding=utf-8
"""Tests for util"""

# stdlib imports
import sys
import uuid
# non-stdlib imports
import pytest
# module under test
import blobxfer.util


def test_on_python2():
    py2 = sys.version_info.major == 2
    assert py2 == blobxfer.util.on_python2()


def test_is_none_or_empty():
    a = None
    assert blobxfer.util.is_none_or_empty(a)
    a = []
    assert blobxfer.util.is_none_or_empty(a)
    a = {}
    assert blobxfer.util.is_none_or_empty(a)
    a = ''
    assert blobxfer.util.is_none_or_empty(a)
    a = 'asdf'
    assert not blobxfer.util.is_none_or_empty(a)
    a = ['asdf']
    assert not blobxfer.util.is_none_or_empty(a)
    a = {'asdf': 0}
    assert not blobxfer.util.is_none_or_empty(a)
    a = [None]
    assert not blobxfer.util.is_none_or_empty(a)


def test_is_not_empty():
    a = None
    assert not blobxfer.util.is_not_empty(a)
    a = []
    assert not blobxfer.util.is_not_empty(a)
    a = {}
    assert not blobxfer.util.is_not_empty(a)
    a = ''
    assert not blobxfer.util.is_not_empty(a)
    a = 'asdf'
    assert blobxfer.util.is_not_empty(a)
    a = ['asdf']
    assert blobxfer.util.is_not_empty(a)
    a = {'asdf': 0}
    assert blobxfer.util.is_not_empty(a)
    a = [None]
    assert blobxfer.util.is_not_empty(a)


def test_merge_dict():
    with pytest.raises(ValueError):
        blobxfer.util.merge_dict(1, 2)

    a = {'a_only': 42, 'a_and_b': 43,
         'a_only_dict': {'a': 44}, 'a_and_b_dict': {'a_o': 45, 'a_a_b': 46}}
    b = {'b_only': 45, 'a_and_b': 46,
         'b_only_dict': {'a': 47}, 'a_and_b_dict': {'b_o': 48, 'a_a_b': 49}}
    c = blobxfer.util.merge_dict(a, b)
    assert c['a_only'] == 42
    assert c['b_only'] == 45
    assert c['a_and_b_dict']['a_o'] == 45
    assert c['a_and_b_dict']['b_o'] == 48
    assert c['a_and_b_dict']['a_a_b'] == 49
    assert c['b_only_dict']['a'] == 47
    assert c['a_and_b'] == 46
    assert a['a_only'] == 42
    assert a['a_and_b'] == 43
    assert b['b_only'] == 45
    assert b['a_and_b'] == 46


def test_scantree(tmpdir):
    tmpdir.mkdir('abc')
    abcpath = tmpdir.join('abc')
    abcpath.join('hello.txt').write('hello')
    abcpath.mkdir('def')
    defpath = abcpath.join('def')
    defpath.join('world.txt').write('world')
    found = set()
    for de in blobxfer.util.scantree(str(tmpdir.dirpath())):
        if de.name != '.lock':
            found.add(de.name)
    assert 'hello.txt' in found
    assert 'world.txt' in found
    assert len(found) == 2


def test_get_mime_type():
    a = 'b.txt'
    mt = blobxfer.util.get_mime_type(a)
    assert mt == 'text/plain'
    a = 'c.probably_cant_determine_this'
    mt = blobxfer.util.get_mime_type(a)
    assert mt == 'application/octet-stream'


def test_base64_encode_as_string():
    a = b'abc'
    enc = blobxfer.util.base64_encode_as_string(a)
    assert type(enc) != bytes
    dec = blobxfer.util.base64_decode_string(enc)
    assert a == dec


def test_compute_md5(tmpdir):
    lpath = str(tmpdir.join('test.tmp'))
    testdata = str(uuid.uuid4())
    with open(lpath, 'wt') as f:
        f.write(testdata)
    md5_file = blobxfer.util.compute_md5_for_file_asbase64(lpath)
    md5_data = blobxfer.util.compute_md5_for_data_asbase64(
        testdata.encode('utf8'))
    assert md5_file == md5_data

    md5_file_page = blobxfer.util.compute_md5_for_file_asbase64(lpath, True)
    assert md5_file != md5_file_page

    # test non-existent file
    with pytest.raises(IOError):
        blobxfer.util.compute_md5_for_file_asbase64(testdata)


def test_page_align_content_length():
    assert 0 == blobxfer.util.page_align_content_length(0)
    assert 512 == blobxfer.util.page_align_content_length(511)
    assert 512 == blobxfer.util.page_align_content_length(512)
    assert 1024 == blobxfer.util.page_align_content_length(513)
