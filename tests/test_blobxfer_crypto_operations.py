# coding=utf-8
"""Tests for crypto operations"""

# stdlib imports
from mock import patch
import os
# non-stdlib imports
import cryptography.hazmat.primitives.asymmetric.rsa
# local imports
# module under test
import blobxfer.crypto.operations as ops


_RSAKEY = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537, key_size=2048,
        backend=cryptography.hazmat.backends.default_backend())


@patch('cryptography.hazmat.primitives.serialization.load_pem_private_key')
def test_load_rsa_private_key_file(patched_load, tmpdir):
    keyfile = tmpdir.join('keyfile')
    keyfile.write('a')
    patched_load.return_value = _RSAKEY

    rv = ops.load_rsa_private_key_file(str(keyfile), None)
    assert rv == _RSAKEY


@patch('cryptography.hazmat.primitives.serialization.load_pem_public_key')
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
