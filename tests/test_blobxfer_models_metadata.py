# coding=utf-8
"""Tests for models metadata"""

# stdlib imports
import json
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import pytest
# module under test
import blobxfer.models.metadata as md


class AseAE(object):
    def __init__(self):
        self.is_encrypted = True
        self.md5 = 'aseae'


def test_get_md5_from_metadata():
    ase = mock.MagicMock()
    ase.is_encrypted = True
    ase.encryption_metadata.blobxfer_extensions.pre_encrypted_content_md5 = \
        'premd5'
    assert md.get_md5_from_metadata(ase) == 'premd5'

    ase.is_encrypted = False
    ase.md5 = 'md5'
    assert md.get_md5_from_metadata(ase) == 'md5'

    ase = AseAE()
    asemd5 = md.get_md5_from_metadata(ase)
    assert asemd5 == 'aseae'


def test_generate_fileattr_metadata():
    with mock.patch('blobxfer.util.on_windows', return_value=True):
        md._FILEATTR_WARNED_ON_WINDOWS = False
        assert md.generate_fileattr_metadata(None, None) is None
        assert md._FILEATTR_WARNED_ON_WINDOWS

    with mock.patch('blobxfer.util.on_windows', return_value=False):
        lp = mock.MagicMock()
        lp.mode = 'mode'
        lp.uid = 0
        lp.gid = 0

        ret = md.generate_fileattr_metadata(lp, {})
        assert len(ret) > 0
        assert md._JSON_KEY_FILE_ATTRIBUTES in ret
        assert md._JSON_KEY_FILE_ATTRIBUTES_POSIX in ret[
            md._JSON_KEY_FILE_ATTRIBUTES]
        assert ret[md._JSON_KEY_FILE_ATTRIBUTES][
            md._JSON_KEY_FILE_ATTRIBUTES_POSIX][
                md._JSON_KEY_FILE_ATTRIBUTES_MODE] == lp.mode
        assert ret[md._JSON_KEY_FILE_ATTRIBUTES][
            md._JSON_KEY_FILE_ATTRIBUTES_POSIX][
                md._JSON_KEY_FILE_ATTRIBUTES_UID] == lp.uid
        assert ret[md._JSON_KEY_FILE_ATTRIBUTES][
            md._JSON_KEY_FILE_ATTRIBUTES_POSIX][
                md._JSON_KEY_FILE_ATTRIBUTES_GID] == lp.gid


def test_fileattr_from_metadata():
    assert md.fileattr_from_metadata(None) is None

    with mock.patch('blobxfer.util.on_windows', return_value=True):
        md._FILEATTR_WARNED_ON_WINDOWS = False
        val = {
            md.JSON_KEY_BLOBXFER_METADATA: json.dumps(
                {md._JSON_KEY_FILE_ATTRIBUTES: {}})
        }
        assert md.fileattr_from_metadata(val) is None
        assert md._FILEATTR_WARNED_ON_WINDOWS

    with mock.patch('blobxfer.util.on_windows', return_value=False):
        lp = mock.MagicMock()
        lp.mode = 'mode'
        lp.uid = 0
        lp.gid = 0

        val = {
            md.JSON_KEY_BLOBXFER_METADATA: json.dumps(
                md.generate_fileattr_metadata(lp, {}))
        }
        assert md.fileattr_from_metadata(val) is not None

        val = {
            md.JSON_KEY_BLOBXFER_METADATA: json.dumps(
                {md._JSON_KEY_FILE_ATTRIBUTES: {}})
        }
        assert md.fileattr_from_metadata(val) is None


def test_create_vecotred_io_next_entry():
    ase = mock.MagicMock()
    ase.client.primary_endpoint = 'ep'
    ase.container = 'cont'
    ase.name = 'name'

    assert md.create_vectored_io_next_entry(ase) == 'ep;cont;name'


def test_explode_vectored_io_next_entry():
    entry = 'sa.blob.core.windows.net;cont;name;'

    vne = md.explode_vectored_io_next_entry(entry)
    assert vne.storage_account_name == 'sa'
    assert vne.endpoint == 'core.windows.net'
    assert vne.container == 'cont'
    assert vne.name == 'name'


def test_remove_vectored_io_slice_suffix_from_name():
    name = 'abc.bxslice-100'
    assert md.remove_vectored_io_slice_suffix_from_name(name, 100) == 'abc'

    name = 'abc.bob'
    assert md.remove_vectored_io_slice_suffix_from_name(name, 0) == 'abc.bob'


def test_generate_vectored_io_stripe_metadata():
    lp = mock.MagicMock()
    lp.total_size = 100
    lp.view.fd_start = 0
    lp.view.total_slices = 2
    lp.view.slice_num = 0
    lp.view.next = 'next'

    ret = md.generate_vectored_io_stripe_metadata(lp, {})
    assert len(ret) > 0
    assert md._JSON_KEY_VECTORED_IO in ret
    assert md._JSON_KEY_VECTORED_IO_STRIPE == ret[md._JSON_KEY_VECTORED_IO][
        md._JSON_KEY_VECTORED_IO_MODE]
    assert ret[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_STRIPE][
        md._JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SIZE] == lp.total_size
    assert ret[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_STRIPE][
        md._JSON_KEY_VECTORED_IO_STRIPE_OFFSET_START] == lp.view.fd_start
    assert ret[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_STRIPE][
        md._JSON_KEY_VECTORED_IO_STRIPE_TOTAL_SLICES] == lp.view.total_slices
    assert ret[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_STRIPE][
        md._JSON_KEY_VECTORED_IO_STRIPE_SLICE_ID] == lp.view.slice_num
    assert ret[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_STRIPE][
        md._JSON_KEY_VECTORED_IO_STRIPE_NEXT] == lp.view.next


def test_vectored_io_from_metadata():
    assert md.vectored_io_from_metadata(None) is None

    lp = mock.MagicMock()
    lp.total_size = 100
    lp.view.fd_start = 0
    lp.view.total_slices = 2
    lp.view.slice_num = 0
    lp.view.next = 'sa.blob.core.windows.net;cont;name;'

    val = {
        md.JSON_KEY_BLOBXFER_METADATA: json.dumps(
            md.generate_vectored_io_stripe_metadata(lp, {}))
    }
    vio = md.vectored_io_from_metadata(val)
    assert vio.total_size == lp.total_size
    assert vio.offset_start == lp.view.fd_start
    assert vio.total_slices == lp.view.total_slices
    assert vio.slice_id == lp.view.slice_num
    assert type(vio.next) == md.VectoredNextEntry

    lp = mock.MagicMock()
    lp.total_size = 100
    lp.view.fd_start = 0
    lp.view.total_slices = 2
    lp.view.slice_num = 0
    lp.view.next = None

    val = {
        md.JSON_KEY_BLOBXFER_METADATA: json.dumps(
            md.generate_vectored_io_stripe_metadata(lp, {}))
    }
    vio = md.vectored_io_from_metadata(val)
    assert vio.total_size == lp.total_size
    assert vio.offset_start == lp.view.fd_start
    assert vio.total_slices == lp.view.total_slices
    assert vio.slice_id == lp.view.slice_num
    assert vio.next is None

    tmp = md.generate_vectored_io_stripe_metadata(lp, {})
    tmp[md._JSON_KEY_VECTORED_IO][md._JSON_KEY_VECTORED_IO_MODE] = 'oops'
    val = {
        md.JSON_KEY_BLOBXFER_METADATA: json.dumps(tmp)
    }
    with pytest.raises(RuntimeError):
        md.vectored_io_from_metadata(val)
