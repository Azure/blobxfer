# coding=utf-8
"""Tests for crypto models"""

# stdlib imports
import copy
import json
# non-stdlib imports
import pytest
# local imports
# module under test
import blobxfer.models.crypto as models
import blobxfer.operations.crypto as ops


_SAMPLE_RSA_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDwlQ0W6O2ixhZM+LYl/ZtUi4lpjFu6+Kt/fyim/LQojaa389yD
e3lqWnAitj13n8uLpv1XuysG2fL+G0AvzT9JJj8gageJRC/8uffhOlxvH/vzfFqU
wQEgwhuv9LXdFcl+mON4TiHqbKsUmggNNPNzSN/P0aohMG8pG8ihyO3uOQIDAQAB
AoGBAIkaKA96RpKQmHzc79DOqgqQSorf9hajR/ismpovQOwrbWs/iddUMmktiOH/
QSA+7Fx1mcK5Y1fQNO4i0X1sVjdasoPvmU7iGVgHQ9TX6F5LGQtDqAKXAH6GpjkF
V7I7nEBs2vtetpzzq8up2nY7fuwPwse44jdLGZjh1pc0HcFRAkEA/F5XdWq5ZYVo
hMyxxhdb+6J8NKZTsWn92tW0s/pGlkgDwrryglpLqNf9MR+Mm906UUVh6ZmsKoxD
kZzA+4S3bwJBAPQLSryk8CUE0uFviYYANq3asn9sDDTGcvEceSGGwbaZOTDVQNQg
7BhLL5vA8Be/xvkXfEaWa1XipmaBI+4WINcCQGQLEiid0jkIldJvQtoAUJqEYzCL
7wmZtuSVazkdsfXJPpRnf9Nk8DFSzjA3DYqMPJ4THyl3neSQDgkfVvFeP0kCQQDu
0OIJKwsJ3ueSznhw1mKrzTkh8pUbTBwNEQUEpv+H9fd+byGqtLD1sRXcwHjzdKt8
9Nubo/VTraGS68tCYQsvAkAYxzwSeX7Gj9/mMBFx1Y5v9sSCqLZQeF7q1ltzkwlK
n3by7Z7RvxXXPjv1YoFQPV0WlA6zo4sm0HwFzA0sbOql
-----END RSA PRIVATE KEY-----
"""

_SAMPLE_ED = \
    {
        "BlobxferExtensions": {
            "PreEncryptedContentMD5": "tc+p1sj+vWGPkawoQ9UKHA=="
        },
        "ContentEncryptionIV": "KjA4Y14+J1p7EJcYWhnKNQ==",
        "EncryptionAgent": {
            "EncryptionAlgorithm": "AES_CBC_256",
            "Protocol": "1.0"
        },
        "EncryptionAuthentication": {
            "Algorithm": "HMAC-SHA256",
            "MessageAuthenticationCode":
            "9oKt5Ett7t1AWahxNq3qcGd5NbZMxLtzSN8Lwqy3PgU="
        },
        "EncryptionMode": "FullBlob",
        "KeyWrappingMetadata": {},
        "WrappedContentKey": {
            "Algorithm": "RSA-OAEP",
            "EncryptedAuthenticationKey":
            "1kO63RxIqIyUp1EW+v2o5VwyhAlrrJiLc+seXnNcVRm0YLHzJYqOrBCz2+"
            "c2do2dJKhzTOXyPsJSwkvQVJ0NuYVUTxf6bzDNip2Ge1jTHnsd5IsljMKy"
            "rSAvHaKs9NxdvDu5Ex6lhKEChnuMtJBq52zCML5+LUd98WkBxdB2az4=",
            "EncryptedKey":
            "yOuWT2txNNzOITtDcjV1Uf3/V+TRn5AKjvOtHt+PRuBgMhq6fOFV8kcJhO"
            "zPxh8bHqydIFM2OQ+ktiETQ5Ibg7OA24hhr+n8Y6nJNpw3cGtP6L/23n8a"
            "a7RMKhmactl3sToFM3xvaXRO0DYuDZeQtPR/DDKPgi2gK641y1THAoc=",
            "KeyId": "private:key1"
        }
    }

_SAMPLE_EDA = \
    {
        "EncryptionMetadataAuthentication": {
            "Algorithm": "HMAC-SHA256",
            "Encoding": "UTF-8",
            "MessageAuthenticationCode":
            "BhJjehtHxgSRIBaITDB6o6ZUt6mdehN0PDkhHtwXTP8="
        }
    }


def test_encryption_metadata_exists():
    md = None
    assert not models.EncryptionMetadata.encryption_metadata_exists(md)

    md = {}
    assert not models.EncryptionMetadata.encryption_metadata_exists(md)

    md = {'encryptiondata': {}}
    assert not models.EncryptionMetadata.encryption_metadata_exists(md)

    md = {'encryptiondata': {'key': 'value'}}
    assert models.EncryptionMetadata.encryption_metadata_exists(md)


def test_create_new_metadata():
    em = models.EncryptionMetadata()
    em.create_new_metadata('key')

    assert em._rsa_public_key == 'key'
    assert em.symmetric_key is not None
    assert em.signing_key is not None
    assert em.content_encryption_iv is not None
    assert em.encryption_agent is not None
    assert em.encryption_mode is not None


def test_convert_from_json(tmpdir):
    keyfile = tmpdir.join('keyfile')
    keyfile.write(_SAMPLE_RSA_KEY)
    rsaprivatekey = ops.load_rsa_private_key_file(str(keyfile), None)

    # test various missing metadata fields
    ced = copy.deepcopy(_SAMPLE_ED)
    ced['EncryptionAgent']['EncryptionAlgorithm'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    ced = copy.deepcopy(_SAMPLE_ED)
    ced['EncryptionAgent']['Protocol'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    ced = copy.deepcopy(_SAMPLE_ED)
    ced['EncryptionAuthentication']['Algorithm'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    ced = copy.deepcopy(_SAMPLE_ED)
    ced['EncryptionMode'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    ced = copy.deepcopy(_SAMPLE_ED)
    ced['WrappedContentKey'].pop('EncryptedAuthenticationKey')
    ced['WrappedContentKey']['Algorithm'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    ceda = copy.deepcopy(_SAMPLE_EDA)
    ceda['EncryptionMetadataAuthentication']['Algorithm'] = 'OOPS'
    md = {
        'encryptiondata': json.dumps(
            _SAMPLE_ED, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(ceda)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    # test failed hmac
    ced = copy.deepcopy(_SAMPLE_ED)
    ced.pop('BlobxferExtensions')
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    with pytest.raises(RuntimeError):
        em.convert_from_json(md, 'blob', rsaprivatekey)

    # test correct path
    md = {
        'encryptiondata': json.dumps(
            _SAMPLE_ED, sort_keys=True, ensure_ascii=False),
        'encryptiondata_authentication': json.dumps(_SAMPLE_EDA)
    }
    em = models.EncryptionMetadata()
    em.convert_from_json(md, 'blob', rsaprivatekey)
    hmac = em.initialize_hmac()
    assert em.wrapped_content_key is not None
    assert em._symkey == em.symmetric_key
    assert em._signkey == em.signing_key
    assert em._symkey is not None
    assert em._signkey is not None
    assert hmac is not None

    em = models.EncryptionMetadata()
    em.convert_from_json(md, 'blob', None)
    assert em.wrapped_content_key is not None
    assert em._symkey is None
    assert em._signkey is None

    ced = copy.deepcopy(_SAMPLE_ED)
    ced['WrappedContentKey'].pop('EncryptedAuthenticationKey')
    md = {
        'encryptiondata': json.dumps(
            ced, sort_keys=True, ensure_ascii=False)
    }
    em = models.EncryptionMetadata()
    em.convert_from_json(md, 'blob', rsaprivatekey)
    hmac = em.initialize_hmac()
    assert em.wrapped_content_key is not None
    assert em._symkey is not None
    assert em._signkey is None
    assert hmac is None


def test_convert_to_json_with_mac(tmpdir):
    keyfile = tmpdir.join('keyfile')
    keyfile.write(_SAMPLE_RSA_KEY)
    rsaprivatekey = ops.load_rsa_private_key_file(str(keyfile), None)
    rsapublickey = rsaprivatekey.public_key()

    em = models.EncryptionMetadata()
    em.create_new_metadata(rsapublickey)
    symkey = em._symkey
    signkey = em._signkey

    encjson = em.convert_to_json_with_mac('md5digest', 'hmacdigest')
    assert encjson is not None
    em.convert_from_json(encjson, 'entityname', rsaprivatekey)
    assert em._symkey == symkey
    assert em._signkey == signkey
