# coding=utf-8
"""Tests for operations azure"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import azure.storage
import azure.storage.blob
import azure.storage.file
import pytest
# local imports
import blobxfer.models.metadata as md
# module under test
import blobxfer.models.azure as azmodels
import blobxfer.operations.azure as azops


def test_storage_credentials():
    creds = azops.StorageCredentials(mock.MagicMock())

    with pytest.raises(ValueError):
        creds.add_storage_account('sa1', '', 'endpoint')

    creds.add_storage_account('sa1', 'somekey1', 'endpoint')

    a = creds.get_storage_account('sa1')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'endpoint'
    assert isinstance(
        a.append_blob_client, azure.storage.blob.AppendBlobService)
    assert isinstance(
        a.block_blob_client, azure.storage.blob.BlockBlobService)
    assert isinstance(
        a.file_client, azure.storage.file.FileService)
    assert isinstance(
        a.page_blob_client, azure.storage.blob.PageBlobService)

    with pytest.raises(KeyError):
        a = creds.get_storage_account('sa2')

    with pytest.raises(ValueError):
        creds.add_storage_account('sa1', 'somekeyxx', 'endpoint')

    creds.add_storage_account('sa2', 'somekey2', 'endpoint2')
    a = creds.get_storage_account('sa1')
    b = creds.get_storage_account('sa2')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'endpoint'
    assert b.name == 'sa2'
    assert b.key == 'somekey2'
    assert b.endpoint == 'endpoint2'


def test_key_is_sas():
    a = azops.StorageAccount(
        'name', 'abcdef', 'endpoint', 10, mock.MagicMock())
    assert not a.is_sas

    a = azops.StorageAccount(
        'name', 'abcdef&blah', 'endpoint', 10, mock.MagicMock())
    assert not a.is_sas

    a = azops.StorageAccount(
        'name', '?abcdef', 'endpoint', 10, mock.MagicMock())
    assert a.is_sas

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'endpoint', 10, mock.MagicMock())
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sv=0&sr=1&sig=2', 'endpoint', 10, mock.MagicMock())
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sig=0&sv=0&sr=1&se=2', 'endpoint', 10, mock.MagicMock())
    assert a.is_sas


def test_container_creation_allowed():
    a = azops.StorageAccount(
        'name', 'abcdef', 'endpoint', 10, mock.MagicMock())
    assert a._container_creation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'endpoint', 10, mock.MagicMock())
    assert not a._container_creation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=a&sig=2', 'endpoint', 10, mock.MagicMock())
    assert not a._container_creation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=c&sig=2', 'endpoint', 10, mock.MagicMock())
    assert a._container_creation_allowed()


@mock.patch('blobxfer.operations.azure.file.get_file_properties')
def test_handle_vectored_io_stripe(patched_gfp):
    creds = mock.MagicMock()
    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.Block
    store_raw_metadata = False
    sa = mock.MagicMock()
    is_file = False
    container = 'cont'
    entity = mock.MagicMock()

    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    # test not first slice
    with mock.patch(
            'blobxfer.models.metadata.vectored_io_from_metadata',
            return_value=md.VectoredStripe(
                next='nextpr',
                offset_start=0,
                slice_id=1,
                total_size=10,
                total_slices=10,
            )):
        for part in asp._handle_vectored_io_stripe(
                creds, options, store_raw_metadata, sa, entity, is_file,
                container, dir=None):
            assert part is None

    # blob test
    with mock.patch(
            'blobxfer.models.metadata.'
            'vectored_io_from_metadata') as patched_vifm:
        patched_vifm.side_effect = [
            md.VectoredStripe(
                next=md.VectoredNextEntry(
                    storage_account_name='sa0',
                    endpoint='core.windows.net',
                    container='cont',
                    name='path-bxslice-0',
                ),
                offset_start=0,
                slice_id=0,
                total_size=2,
                total_slices=2,
            ),
            md.VectoredStripe(
                next=md.VectoredNextEntry(
                    storage_account_name='sa1',
                    endpoint='core.windows.net',
                    container='cont',
                    name='path-bxslice-1',
                ),
                offset_start=1,
                slice_id=1,
                total_size=2,
                total_slices=2,
            ),
        ]
        options.mode = azmodels.StorageModes.Block
        i = 0
        for part in asp._handle_vectored_io_stripe(
                creds, options, store_raw_metadata, sa, entity, is_file,
                container, dir=None):
            i += 1
        assert i == 2

    # file test
    with mock.patch(
            'blobxfer.models.metadata.'
            'vectored_io_from_metadata') as patched_vifm:
        patched_vifm.side_effect = [
            md.VectoredStripe(
                next=md.VectoredNextEntry(
                    storage_account_name='sa0',
                    endpoint='core.windows.net',
                    container='cont',
                    name='path-bxslice-0',
                ),
                offset_start=0,
                slice_id=0,
                total_size=2,
                total_slices=2,
            ),
            md.VectoredStripe(
                next=md.VectoredNextEntry(
                    storage_account_name='sa1',
                    endpoint='core.windows.net',
                    container='cont',
                    name='path-bxslice-1',
                ),
                offset_start=1,
                slice_id=1,
                total_size=2,
                total_slices=2,
            ),
        ]
        options.mode = azmodels.StorageModes.File
        is_file = True
        f = azure.storage.file.models.File(name='path-bxslice-1')
        patched_gfp.side_effect = [f]
        i = 0
        for part in asp._handle_vectored_io_stripe(
                creds, options, store_raw_metadata, sa, entity, is_file,
                container, dir=None):
            i += 1
        assert i == 2


def test_azuresourcepath():
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    with pytest.raises(RuntimeError):
        asp.add_path_with_storage_account('x', 'x')

    assert 'sa' == asp.lookup_storage_account(p)


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.file.list_files')
def test_azuresourcepath_files(patched_lf, patched_em):
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.File
    creds = mock.MagicMock()
    creds.get_storage_account = mock.MagicMock()
    sa = mock.MagicMock()
    sa.file_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    f = azure.storage.file.models.File(name='name')
    patched_lf.side_effect = [[f]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    i = 0
    for file in asp.files(creds, options):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('remote/name')
        assert file.encryption_metadata is None
    assert i == 1

    # test filter
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_lf.side_effect = [[f]]
    assert len(list(asp.files(creds, options))) == 0

    # test no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_lf.side_effect = [[f]]
        assert len(list(asp.files(creds, options))) == 0

    # test encrypted
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    fe = azure.storage.file.models.File(name='name')
    fe.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lf.side_effect = [[fe]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('remote/name')
        assert file.encryption_metadata is not None
    assert i == 1


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.blob.list_blobs')
def test_azuresourcepath_blobs(patched_lb, patched_em):
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.Auto
    creds = mock.MagicMock()
    creds.get_storage_account = mock.MagicMock()
    sa = mock.MagicMock()
    sa.block_blob_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    b = azure.storage.blob.models.Blob(name='name')
    patched_lb.side_effect = [[b]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    i = 0
    for file in asp.files(creds, options):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    # test filter
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_lb.side_effect = [[b]]
    assert len(list(asp.files(creds, options))) == 0

    # test no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_lb.side_effect = [[b]]
        assert len(list(asp.files(creds, options))) == 0

    be = azure.storage.blob.models.Blob(name='name')
    be.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lb.side_effect = [[be]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1


def test_destinationpath():
    dp = azops.DestinationPath()
    sa = mock.MagicMock()
    dp.add_path_with_storage_account('/remote/path/', sa)

    assert len(dp._paths) == 1
    assert len(dp._path_map) == 1

    with pytest.raises(RuntimeError):
        dp.add_path_with_storage_account('/remote/path2/', sa)

    assert dp.lookup_storage_account('/remote/path/') is not None
