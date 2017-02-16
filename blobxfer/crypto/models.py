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
import collections
import hashlib
import hmac
import json
import logging
# non-stdlib imports
# local imports
import blobxfer.crypto.operations
import blobxfer.util


# encryption constants
_AES256_KEYLENGTH_BYTES = 32
_AES256_BLOCKSIZE_BYTES = 16
_HMACSHA256_DIGESTSIZE_BYTES = 32
_AES256CBC_HMACSHA256_OVERHEAD_BYTES = (
    _AES256_BLOCKSIZE_BYTES + _HMACSHA256_DIGESTSIZE_BYTES
)

# named tuples
EncryptionBlobxferExtensions = collections.namedtuple(
    'EncryptionBlobxferExtensions', [
        'pre_encrypted_content_md5',
    ]
)
EncryptionAgent = collections.namedtuple(
    'EncryptionAgent', [
        'encryption_algorithm',
        'protocol',
    ]
)
EncryptionAuthentication = collections.namedtuple(
    'EncryptionAuthentication', [
        'algorithm',
        'message_authentication_code',
    ]
)
EncryptionWrappedContentKey = collections.namedtuple(
    'EncryptionWrappedContentKey', [
        'algorithm',
        'encrypted_authentication_key',
        'encrypted_key',
        'key_id',
    ]
)
EncryptionMetadataAuthentication = collections.namedtuple(
    'EncryptionMetadataAuthentication', [
        'algorithm',
        'encoding',
        'message_authentication_code',
    ]
)


class EncryptionMetadata(object):
    """EncryptionMetadata"""

    # constants
    _ENCRYPTION_MODE = 'FullBlob'
    _ENCRYPTION_PROTOCOL_VERSION = '1.0'
    _ENCRYPTION_ALGORITHM = 'AES_CBC_256'
    _ENCRYPTED_KEY_SCHEME = 'RSA-OAEP'
    _AUTH_ALGORITHM = 'HMAC-SHA256'
    _AUTH_ENCODING_TYPE = 'UTF-8'

    _METADATA_KEY_NAME = 'encryptiondata'
    _METADATA_KEY_AUTH_NAME = 'encryptiondata_authentication'

    _JSON_KEY_ENCRYPTION_MODE = 'EncryptionMode'
    _JSON_KEY_ALGORITHM = 'Algorithm'
    _JSON_KEY_MAC = 'MessageAuthenticationCode'
    _JSON_KEY_ENCRYPTION_AGENT = 'EncryptionAgent'
    _JSON_KEY_PROTOCOL = 'Protocol'
    _JSON_KEY_ENCRYPTION_ALGORITHM = 'EncryptionAlgorithm'
    _JSON_KEY_INTEGRITY_AUTH = 'EncryptionAuthentication'
    _JSON_KEY_WRAPPEDCONTENTKEY = 'WrappedContentKey'
    _JSON_KEY_ENCRYPTED_KEY = 'EncryptedKey'
    _JSON_KEY_ENCRYPTED_AUTHKEY = 'EncryptedAuthenticationKey'
    _JSON_KEY_CONTENT_IV = 'ContentEncryptionIV'
    _JSON_KEY_KEYID = 'KeyId'
    _JSON_KEY_BLOBXFER_EXTENSIONS = 'BlobxferExtensions'
    _JSON_KEY_PREENCRYPTED_MD5 = 'PreEncryptedContentMD5'

    _JSON_KEY_AUTH_METAAUTH = 'EncryptionMetadataAuthentication'
    _JSON_KEY_AUTH_ENCODING = 'Encoding'

    def __init__(self):
        # type: (EncryptionMetadata) -> None
        """Ctor for EncryptionMetadata
        :param EncryptionMetadata self: this
        """
        self.blobxfer_extensions = None
        self.content_encryption_iv = None
        self.encryption_agent = None
        self.encryption_authentication = None
        self.encryption_mode = None
        self.key_wrapping_metadata = {}
        self.wrapped_content_key = None
        self.encryption_metadata_authentication = None
        self._symkey = None
        self._signkey = None

    @staticmethod
    def encryption_metadata_exists(md):
        # type: (dict) -> bool
        """Check if encryption metadata exists in json metadata
        :param dict md: metadata dictionary
        :rtype: bool
        :return: if encryption metadata exists
        """
        try:
            if blobxfer.util.is_not_empty(
                    md[EncryptionMetadata._METADATA_KEY_NAME]):
                return True
        except (KeyError, TypeError):
            pass
        return False

    def convert_from_json(self, md, blobname, rsaprivatekey):
        # type: (EncryptionMetadata, dict, str,
        #        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey)
        #        -> None
        """Read metadata json into objects
        :param EncryptionMetadata self: this
        :param dict md: metadata dictionary
        :param str blobname: blob name
        :param rsaprivatekey: RSA private key
        :type rsaprivatekey:
            cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
        """
        # populate from encryption data
        ed = json.loads(md[EncryptionMetadata._METADATA_KEY_NAME])
        try:
            self.blobxfer_extensions = EncryptionBlobxferExtensions(
                pre_encrypted_content_md5=ed[
                    EncryptionMetadata._JSON_KEY_BLOBXFER_EXTENSIONS][
                        EncryptionMetadata._JSON_KEY_PREENCRYPTED_MD5],
            )
        except KeyError:
            pass
        self.content_encryption_iv = ed[
            EncryptionMetadata._JSON_KEY_CONTENT_IV]
        self.encryption_agent = EncryptionAgent(
            encryption_algorithm=ed[
                EncryptionMetadata._JSON_KEY_ENCRYPTION_AGENT][
                    EncryptionMetadata._JSON_KEY_ENCRYPTION_ALGORITHM],
            protocol=ed[
                EncryptionMetadata._JSON_KEY_ENCRYPTION_AGENT][
                    EncryptionMetadata._JSON_KEY_PROTOCOL],
        )
        if (self.encryption_agent.encryption_algorithm !=
                EncryptionMetadata._ENCRYPTION_ALGORITHM):
            raise RuntimeError('{}: unknown block cipher: {}'.format(
                blobname, self.encryption_agent.encryption_algorithm))
        if (self.encryption_agent.protocol !=
                EncryptionMetadata._ENCRYPTION_PROTOCOL_VERSION):
            raise RuntimeError('{}: unknown encryption protocol: {}'.format(
                blobname, self.encryption_agent.protocol))
        self.encryption_authentication = EncryptionAuthentication(
            algorithm=ed[
                EncryptionMetadata._JSON_KEY_INTEGRITY_AUTH][
                    EncryptionMetadata._JSON_KEY_ALGORITHM],
            message_authentication_code=ed[
                EncryptionMetadata._JSON_KEY_INTEGRITY_AUTH][
                    EncryptionMetadata._JSON_KEY_MAC],
        )
        if (self.encryption_authentication.algorithm !=
                EncryptionMetadata._AUTH_ALGORITHM):
            raise RuntimeError(
                '{}: unknown integrity/auth method: {}'.format(
                    blobname, self.encryption_authentication.algorithm))
        self.encryption_mode = ed[
            EncryptionMetadata._JSON_KEY_ENCRYPTION_MODE]
        if self.encryption_mode != EncryptionMetadata._ENCRYPTION_MODE:
            raise RuntimeError(
                '{}: unknown encryption mode: {}'.format(
                    blobname, self.encryption_mode))
        try:
            _eak = ed[EncryptionMetadata._JSON_KEY_WRAPPEDCONTENTKEY][
                EncryptionMetadata._JSON_KEY_ENCRYPTED_AUTHKEY]
        except KeyError:
            _eak = None
        self.wrapped_content_key = EncryptionWrappedContentKey(
            algorithm=ed[
                EncryptionMetadata._JSON_KEY_WRAPPEDCONTENTKEY][
                    EncryptionMetadata._JSON_KEY_ALGORITHM],
            encrypted_authentication_key=_eak,
            encrypted_key=ed[
                EncryptionMetadata._JSON_KEY_WRAPPEDCONTENTKEY][
                    EncryptionMetadata._JSON_KEY_ENCRYPTED_KEY],
            key_id=ed[
                EncryptionMetadata._JSON_KEY_WRAPPEDCONTENTKEY][
                    EncryptionMetadata._JSON_KEY_KEYID],
        )
        if (self.wrapped_content_key.algorithm !=
                EncryptionMetadata._ENCRYPTED_KEY_SCHEME):
            raise RuntimeError('{}: unknown key encryption scheme: {}'.format(
                blobname, self.wrapped_content_key.algorithm))
        # if RSA key is a public key, stop here as keys cannot be decrypted
        if rsaprivatekey is None:
            return
        # decrypt symmetric key
        self._symkey = blobxfer.crypto.operations.\
            rsa_decrypt_base64_encoded_key(
                rsaprivatekey, self.wrapped_content_key.encrypted_key)
        # decrypt signing key, if it exists
        if blobxfer.util.is_not_empty(
                self.wrapped_content_key.encrypted_authentication_key):
            self._signkey = blobxfer.crypto.operations.\
                rsa_decrypt_base64_encoded_key(
                    rsaprivatekey,
                    self.wrapped_content_key.encrypted_authentication_key)
        else:
            self._signkey = None
        # populate from encryption data authentication
        try:
            eda = json.loads(md[EncryptionMetadata._METADATA_KEY_AUTH_NAME])
        except KeyError:
            pass
        else:
            self.encryption_metadata_authentication = \
                EncryptionMetadataAuthentication(
                    algorithm=eda[
                        EncryptionMetadata._JSON_KEY_AUTH_METAAUTH][
                            EncryptionMetadata._JSON_KEY_ALGORITHM],
                    encoding=eda[
                        EncryptionMetadata._JSON_KEY_AUTH_METAAUTH][
                            EncryptionMetadata._JSON_KEY_AUTH_ENCODING],
                    message_authentication_code=eda[
                        EncryptionMetadata._JSON_KEY_AUTH_METAAUTH][
                            EncryptionMetadata._JSON_KEY_MAC],
                )
            if (self.encryption_metadata_authentication.algorithm !=
                    EncryptionMetadata._AUTH_ALGORITHM):
                raise RuntimeError(
                    '{}: unknown integrity/auth method: {}'.format(
                        blobname,
                        self.encryption_metadata_authentication.algorithm))
            # verify hmac
            authhmac = base64.b64decode(
                self.encryption_metadata_authentication.
                message_authentication_code)
            bmeta = md[EncryptionMetadata._METADATA_KEY_NAME].encode(
                self.encryption_metadata_authentication.encoding)
            hmacsha256 = hmac.new(self._signkey, digestmod=hashlib.sha256)
            hmacsha256.update(bmeta)
            if hmacsha256.digest() != authhmac:
                raise RuntimeError(
                    '{}: encryption metadata authentication failed'.format(
                        blobname))

    def convert_to_json_with_mac(self):
        pass
