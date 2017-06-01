# coding=utf-8
"""Tests for crypto operations"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
import os
import time
# non-stdlib imports
import cryptography.hazmat.primitives.asymmetric.rsa
# local imports
import blobxfer.models.download
# module under test
import blobxfer.operations.crypto as ops


_RSAKEY = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
        backend=cryptography.hazmat.backends.default_backend())


@mock.patch(
    'cryptography.hazmat.primitives.serialization.load_pem_private_key')
def test_load_rsa_private_key_file(patched_load, tmpdir):
    keyfile = tmpdir.join('keyfile')
    keyfile.write('a')
    patched_load.return_value = _RSAKEY

    rv = ops.load_rsa_private_key_file(str(keyfile), None)
    assert rv == _RSAKEY


@mock.patch('cryptography.hazmat.primitives.serialization.load_pem_public_key')
def test_load_rsa_public_key_file(patched_load, tmpdir):
    keyfile = tmpdir.join('keyfile')
    keyfile.write('b')
    patched_load.return_value = 'rv'

    rv = ops.load_rsa_public_key_file(str(keyfile))
    assert rv == 'rv'


def test_rsa_encrypt_decrypt_keys():
    symkey = os.urandom(32)
    enckey = ops.rsa_encrypt_key_base64_encoded(_RSAKEY, None, symkey)
    assert enckey is not None
    plainkey = ops.rsa_decrypt_base64_encoded_key(_RSAKEY, enckey)
    assert symkey == plainkey


def test_pkcs7_padding():
    buf = os.urandom(32)
    pbuf = ops.pkcs7_pad(buf)
    buf2 = ops.pkcs7_unpad(pbuf)
    assert buf == buf2


def test_aes_cbc_encryption():
    enckey = ops.aes256_generate_random_key()
    assert len(enckey) == ops._AES256_KEYLENGTH_BYTES

    # test random binary data, unaligned
    iv = os.urandom(16)
    plaindata = os.urandom(31)
    encdata = ops.aes_cbc_encrypt_data(enckey, iv, plaindata, True)
    assert encdata != plaindata
    decdata = ops.aes_cbc_decrypt_data(enckey, iv, encdata, True)
    assert decdata == plaindata

    # test random binary data aligned on boundary
    plaindata = os.urandom(32)
    encdata = ops.aes_cbc_encrypt_data(enckey, iv, plaindata, True)
    assert encdata != plaindata
    decdata = ops.aes_cbc_decrypt_data(enckey, iv, encdata, True)
    assert decdata == plaindata

    # test "text" data
    plaintext = 'attack at dawn!'
    plaindata = plaintext.encode('utf8')
    encdata = ops.aes_cbc_encrypt_data(enckey, iv, plaindata, True)
    assert encdata != plaindata
    decdata = ops.aes_cbc_decrypt_data(enckey, iv, encdata, True)
    assert decdata == plaindata
    assert plaindata.decode('utf8') == plaintext

    # test unpadded
    plaindata = os.urandom(32)
    encdata = ops.aes_cbc_encrypt_data(enckey, iv, plaindata, False)
    assert encdata != plaindata
    decdata = ops.aes_cbc_decrypt_data(enckey, iv, encdata, False)
    assert decdata == plaindata


def test_cryptooffload_decrypt(tmpdir):
    symkey = ops.aes256_generate_random_key()
    iv = os.urandom(16)
    plainlen = 16
    plaindata = os.urandom(plainlen)
    encdata = ops.aes_cbc_encrypt_data(symkey, iv, plaindata, False)

    afile = tmpdir.join('a')
    afile.write(encdata, mode='wb')
    hmacfile = str(afile)
    bfile = tmpdir.join('b')
    bfile.ensure(file=True)

    a = None
    try:
        a = ops.CryptoOffload(1)
        offsets = blobxfer.models.download.Offsets(
            chunk_num=0,
            fd_start=0,  # this matters!
            num_bytes=2,
            range_end=3,
            range_start=4,
            unpad=False,
        )
        a.add_decrypt_chunk(
            str(bfile), 0, offsets, symkey, iv, hmacfile)
        i = 33
        checked = False
        while i > 0:
            result = a.pop_done_queue()
            if result is None:
                time.sleep(0.3)
                i -= 1
                continue
            assert result == (str(bfile), offsets)
            checked = True
            break
        assert checked
        assert bfile.stat().size == plainlen
        decdata = bfile.read(mode='rb')
        assert decdata == plaindata
    finally:
        if a is not None:
            a.finalize_processes()
