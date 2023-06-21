# coding=utf-8
"""Tests for util"""

# stdlib imports
import datetime
import time
# non-stdlib imports
import dateutil.tz
import pytest
# module under test
import blobxfer.util


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


def test_datetime_now():
    a = blobxfer.util.datetime_now()
    assert type(a) == datetime.datetime


def test_datetime_from_timestamp():
    ts = time.time()
    a = blobxfer.util.datetime_from_timestamp(ts)
    assert type(a) == datetime.datetime

    b = a.astimezone(dateutil.tz.tzutc())
    assert(b) == blobxfer.util.datetime_from_timestamp(ts, as_utc=True)


def test_scantree(tmpdir):
    tmpdir.mkdir('abc')
    abcpath = tmpdir.join('abc')
    abcpath.join('hello.txt').write('hello')
    abcpath.mkdir('def')
    defpath = abcpath.join('def')
    defpath.join('world.txt').write('world')
    found = set()
    for de in blobxfer.util.scantree(str(tmpdir)):
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


def test_new_md5_hasher():
    assert blobxfer.util.new_md5_hasher() is not None


def test_page_align_content_length():
    assert 0 == blobxfer.util.page_align_content_length(0)
    assert 512 == blobxfer.util.page_align_content_length(1)
    assert 512 == blobxfer.util.page_align_content_length(511)
    assert 512 == blobxfer.util.page_align_content_length(512)
    assert 1024 == blobxfer.util.page_align_content_length(513)
    assert 1024 == blobxfer.util.page_align_content_length(1023)
    assert 1024 == blobxfer.util.page_align_content_length(1024)
    assert 1536 == blobxfer.util.page_align_content_length(1025)


def test_normalize_azure_path():
    a = '\\cont\\r1\\r2\\r3\\'
    b = blobxfer.util.normalize_azure_path(a)
    assert b == 'cont/r1/r2/r3'

    a = '/cont/r1/r2/r3/'
    b = blobxfer.util.normalize_azure_path(a)
    assert b == 'cont/r1/r2/r3'

    a = '/cont\\r1/r2\\r3/'
    b = blobxfer.util.normalize_azure_path(a)
    assert b == 'cont/r1/r2/r3'

    with pytest.raises(ValueError):
        blobxfer.util.normalize_azure_path('')


def test_explode_azure_path():
    p = 'cont'
    cont, rpath = blobxfer.util.explode_azure_path(p)
    assert cont == 'cont'
    assert rpath == ''

    p = 'cont/'
    cont, rpath = blobxfer.util.explode_azure_path(p)
    assert cont == 'cont'
    assert rpath == ''

    p = 'cont/a/'
    cont, rpath = blobxfer.util.explode_azure_path(p)
    assert cont == 'cont'
    assert rpath == 'a'

    p = '/some/remote/path'
    cont, rpath = blobxfer.util.explode_azure_path(p)
    assert cont == 'some'
    assert rpath == 'remote/path'


def test_blob_is_snapshot():
    a = '/cont/a?snapshot=2017-02-23T22:21:14.8121864Z'
    assert blobxfer.util.blob_is_snapshot(a)

    a = '/cont/a?snapshot=abc'
    assert not blobxfer.util.blob_is_snapshot(a)

    a = '/cont/a?snapshot='
    assert not blobxfer.util.blob_is_snapshot(a)

    a = '/cont/a?snapshot=2017-02-23T22:21:14.8121864Z?snapshot='
    assert not blobxfer.util.blob_is_snapshot(a)


def test_parse_blob_snapshot_parameter():
    base = '/cont/a'
    param = '2017-02-23T22:21:14.8121864Z'

    a = base + '?snapshot=' + param
    assert blobxfer.util.parse_blob_snapshot_parameter(a) == (base, param)

    a = base + '?snapshot='
    assert blobxfer.util.parse_blob_snapshot_parameter(a) is None


def test_parse_fileshare_or_file_snapshot_parameter():
    base = 'fs/a'
    param = '2017-02-23T22:21:14.8121864Z'

    a = base + '?sharesnapshot=' + param
    assert blobxfer.util.parse_fileshare_or_file_snapshot_parameter(a) == (
        base, param)

    a = base + '?sharesnapshot=abc'
    assert blobxfer.util.parse_fileshare_or_file_snapshot_parameter(a) == (
        a, None)

    base = 'fs'

    a = base + '?snapshot=' + param
    assert blobxfer.util.parse_fileshare_or_file_snapshot_parameter(a) == (
        base, param)

    a = base + '?snapshot=abc'
    assert blobxfer.util.parse_fileshare_or_file_snapshot_parameter(a) == (
        a, None)


def test_explode_azure_storage_url():
    url = 'https://sa.blob.core.windows.net/cont/file'
    sa, mode, ep, rpath, sas = blobxfer.util.explode_azure_storage_url(url)
    assert sa == 'sa'
    assert mode == 'blob'
    assert ep == 'core.windows.net'
    assert rpath == 'cont/file'
    assert sas is None

    url = 'https://sa2.file.core.usgovcloudapi.net/cont2/file2?sas'
    sa, mode, ep, rpath, sas = blobxfer.util.explode_azure_storage_url(url)
    assert sa == 'sa2'
    assert mode == 'file'
    assert ep == 'core.usgovcloudapi.net'
    assert rpath == 'cont2/file2'
    assert sas == 'sas'

    url = 'https://managed-disk.z31.blob.storage.azure.net/randcont/abcd?sas'
    sa, mode, ep, rpath, sas = blobxfer.util.explode_azure_storage_url(url)
    assert sa == 'managed-disk'
    assert mode == 'blob'
    assert ep == 'storage.azure.net'
    assert rpath == 'randcont/abcd'
    assert sas == 'sas'
