# Copyright (c) Microsoft Corporation
#
# All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# compat imports
from __future__ import (
    absolute_import, division, print_function, unicode_literals
)
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip)
# stdlib imports
import base64
import logging
# non-stdlib imports
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.asymmetric.padding
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes
import cryptography.hazmat.primitives.constant_time
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.padding
import cryptography.hazmat.primitives.serialization
# local imports
import blobxfer.util


def load_rsa_private_key_file(rsakeyfile, passphrase):
    # type: (str, str) ->
    #        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """Load an RSA Private key PEM file with passphrase if specified
    :param str rsakeyfile: RSA private key PEM file to load
    :param str passphrase: optional passphrase
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    :return: RSAPrivateKey
    """
    with open(rsakeyfile, 'rb') as keyfile:
        return cryptography.hazmat.primitives.serialization.\
            load_pem_private_key(
                keyfile.read(),
                passphrase,
                backend=cryptography.hazmat.backends.default_backend()
            )


def load_rsa_public_key_file(rsakeyfile):
    # type: (str, str) ->
    #        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    """Load an RSA Public key PEM file
    :param str rsakeyfile: RSA public key PEM file to load
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    :return: RSAPublicKey
    """
    with open(rsakeyfile, 'rb') as keyfile:
        return cryptography.hazmat.primitives.serialization.\
            load_pem_public_key(
                keyfile.read(),
                backend=cryptography.hazmat.backends.default_backend()
            )


def rsa_decrypt_base64_encoded_key(rsaprivatekey, enckey):
    # type: (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
    #        str) -> bytes
    """Decrypt an RSA encrypted key encoded as base64
    :param rsaprivatekey: RSA private key
    :type rsaprivatekey:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    :param str enckey: base64-encoded key
    :rtype: bytes
    :return: decrypted key
    """
    return rsaprivatekey.decrypt(
        base64.b64decode(enckey),
        cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                algorithm=cryptography.hazmat.primitives.hashes.SHA1()
            ),
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            label=None,
        )
    )


def rsa_encrypt_key_base64_encoded(rsaprivatekey, rsapublickey, plainkey):
    # type: (cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey,
    #        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey,
    #        bytes) -> str
    """Encrypt a plaintext key using RSA and PKCS1_OAEP padding
    :param rsaprivatekey: RSA private key
    :type rsaprivatekey:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    :param rsapublickey: RSA public key
    :type rsapublickey:
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey
    :param bytes plainkey: plain key
    :rtype: str
    :return: encrypted key
    """
    if rsapublickey is None:
        rsapublickey = rsaprivatekey.public_key()
    enckey = rsapublickey.encrypt(
        plainkey, cryptography.hazmat.primitives.asymmetric.padding.OAEP(
            mgf=cryptography.hazmat.primitives.asymmetric.padding.MGF1(
                algorithm=cryptography.hazmat.primitives.hashes.SHA1()),
            algorithm=cryptography.hazmat.primitives.hashes.SHA1(),
            label=None))
    return blobxfer.util.base64_encode_as_string(enckey)
