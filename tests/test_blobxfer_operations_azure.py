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
import azure.storage.blob
import azure.storage.file
import pytest
# local imports
import blobxfer.models.metadata as md
import blobxfer.models.options
# module under test
import blobxfer.models.azure as azmodels
import blobxfer.operations.azure as azops


def test_storage_credentials():
    go = mock.MagicMock()
    go.timeout.max_retries = None

    creds = azops.StorageCredentials(go)

    with pytest.raises(ValueError):
        creds.add_storage_account('sa1', '', 'core.windows.net')

    with pytest.raises(ValueError):
        creds.add_storage_account(
            'sa1', 'somekey1', 'https://blob.core.windows.net')

    creds.add_storage_account('sa1', 'somekey1', 'core.windows.net')

    a = creds.get_storage_account('sa1')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'core.windows.net'
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
        creds.add_storage_account('sa1', 'somekeyxx', 'core.windows.net')

    creds.add_storage_account('sa2', 'somekey2', 'core.cloudapi.de')
    a = creds.get_storage_account('sa1')
    b = creds.get_storage_account('sa2')
    assert a.name == 'sa1'
    assert a.key == 'somekey1'
    assert a.endpoint == 'core.windows.net'
    assert b.name == 'sa2'
    assert b.key == 'somekey2'
    assert b.endpoint == 'core.cloudapi.de'


def test_key_is_sas():
    to = mock.MagicMock()
    to.max_retries = None

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, mock.MagicMock())
    assert not a.is_sas

    with pytest.raises(ValueError):
        a = azops.StorageAccount(
            'name', 'abcdef&blah', 'core.windows.net', 10, to, None)

    a = azops.StorageAccount(
        'name', '?abcdef', 'core.windows.net', 10, to, None)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'core.windows.net', 10, to, None)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sv=0&sr=1&sig=2', 'core.windows.net', 10, to, None)
    assert a.is_sas

    a = azops.StorageAccount(
        'name', 'sig=0&sv=0&sr=1&se=2', 'core.windows.net', 10, to, None)
    assert a.is_sas


def test_container_manipulation_allowed():
    to = mock.MagicMock()
    to.max_retries = None

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, None)
    assert a._container_manipulation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'core.windows.net', 10, to, None)
    assert not a._container_manipulation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=ao&sig=2', 'core.windows.net', 10, to, None)
    assert not a._container_manipulation_allowed()

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sig=2', 'core.windows.net', 10, to, None)
    assert a._container_manipulation_allowed()


def test_ensure_object_manipulation_allowed():
    to = mock.MagicMock()
    to.max_retries = None

    with pytest.raises(ValueError):
        azops.StorageAccount(
            'name', '?sv=0&sr=1&srt=c&sig=2', 'core.windows.net', 10, to, None)

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, None)
    assert a._ensure_object_manipulation_allowed()


def test_credential_allows_container_list():
    to = mock.MagicMock()
    to.max_retries = None

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=l&sig=2', 'core.windows.net', 10, to,
        None)
    assert a._credential_allows_container_list()
    assert a.can_list_container_objects

    a = azops.StorageAccount(
        'name', '?sv=0&sr=s&sp=l&sig=2', 'core.windows.net', 10, to,
        None)
    assert a._credential_allows_container_list()
    assert a.can_list_container_objects

    a = azops.StorageAccount(
        'name', '?sv=0&sr=f&sp=rl&sig=2', 'core.windows.net', 10, to,
        None)
    assert not a._credential_allows_container_list()
    assert not a.can_list_container_objects

    a = azops.StorageAccount(
        'name', '?sv=0&si=policy&sig=2', 'core.windows.net', 10, to, None)
    assert a._credential_allows_container_list()
    assert a.can_list_container_objects

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=r&sig=2', 'core.windows.net', 10, to,
        None)
    assert not a._credential_allows_container_list()
    assert not a.can_list_container_objects

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, None)
    assert a._credential_allows_container_list()
    assert a.can_list_container_objects


def test_credential_allows_object_read():
    to = mock.MagicMock()
    to.max_retries = None

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=r&sig=2', 'core.windows.net', 10, to,
        None)
    assert a._credential_allows_object_read()
    assert a.can_read_object

    a = azops.StorageAccount(
        'name', '?sv=0&si=policy&sig=2', 'core.windows.net', 10, to, None)
    assert a._credential_allows_object_read()
    assert a.can_read_object

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=w&sig=2', 'core.windows.net', 10, to,
        None)
    assert not a._credential_allows_object_read()
    assert not a.can_read_object

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, None)
    assert a._credential_allows_object_read()
    assert a.can_read_object


def test_credential_allows_object_write():
    to = mock.MagicMock()
    to.max_retries = None

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=w&sig=2', 'core.windows.net', 10, to,
        None)
    assert a._credential_allows_object_write()
    assert a.can_write_object

    a = azops.StorageAccount(
        'name', '?sv=0&si=policy&sig=2', 'core.windows.net', 10, to, None)
    assert a._credential_allows_object_write()
    assert a.can_write_object

    a = azops.StorageAccount(
        'name', '?sv=0&sr=1&srt=co&sp=r&sig=2', 'core.windows.net', 10, to,
        None)
    assert not a._credential_allows_object_write()
    assert not a.can_write_object

    a = azops.StorageAccount(
        'name', 'AAAAAA==', 'core.windows.net', 10, to, None)
    assert a._credential_allows_object_write()
    assert a.can_write_object


@mock.patch('blobxfer.operations.azure.file.get_file_properties')
@mock.patch('blobxfer.operations.azure.blob.get_blob_properties')
def test_handle_vectored_io_stripe(patched_gbp, patched_gfp):
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
            side_effect=[md.VectoredStripe(
                next='nextpr',
                offset_start=0,
                slice_id=1,
                total_size=10,
                total_slices=10,
            )]):
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
                next=None,
                offset_start=1,
                slice_id=1,
                total_size=2,
                total_slices=2,
            ),
        ]
        options.mode = azmodels.StorageModes.Block
        b0 = azure.storage.blob.models.Blob(name='path-bxslice-0')
        b1 = azure.storage.blob.models.Blob(name='path-bxslice-1')
        patched_gbp.side_effect = [b0, b1]
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
                next=None,
                offset_start=1,
                slice_id=1,
                total_size=2,
                total_slices=2,
            ),
        ]
        options.mode = azmodels.StorageModes.File
        is_file = True
        f0 = azure.storage.file.models.File(name='path-bxslice-0')
        f1 = azure.storage.file.models.File(name='path-bxslice-1')
        patched_gfp.side_effect = [f0, f1]
        i = 0
        for part in asp._handle_vectored_io_stripe(
                creds, options, store_raw_metadata, sa, entity, is_file,
                container, dir=None):
            i += 1
        assert i == 2


@mock.patch('requests.head')
def test_populate_from_arbitrary_url(patched_rh):
    response = mock.MagicMock()
    response.headers = {
        'Content-Length': 10
    }
    patched_rh.return_value = response

    asp = azops.SourcePath()
    ase = asp._populate_from_arbitrary_url('https://host/remote/path')
    assert ase.size == 10
    assert ase.path == 'https://host/remote/path'
    assert ase.is_arbitrary_url


def test_azuresourcepath():
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    with pytest.raises(RuntimeError):
        asp.add_path_with_storage_account('x', 'x')

    assert 'sa' == asp.lookup_storage_account(p)

    asp = azops.SourcePath()
    asp.add_arbitrary_remote_url('https://host/remote/path')
    assert 'https://host/remote/path' in asp._paths


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.file.list_files')
@mock.patch('blobxfer.operations.azure.file.get_file_properties')
@mock.patch('blobxfer.operations.azure.file.check_if_single_file')
def test_azuresourcepath_files(
        patched_cisf, patched_gfp, patched_lf, patched_em):
    p = 'cont/name'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.File
    creds = mock.MagicMock()
    sa = mock.MagicMock()
    sa.file_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    f = azure.storage.file.models.File(name='name')
    patched_cisf.return_value = (False, None)
    patched_lf.side_effect = [[f]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    # test no read access
    sa.can_read_object = False
    with pytest.raises(RuntimeError):
        next(asp.files(creds, options, False))
    sa.can_read_object = True

    # test normal container path
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('name')
        assert file.encryption_metadata is None
    assert i == 1

    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.File
    creds = mock.MagicMock()
    sa = mock.MagicMock()
    sa.file_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    f = azure.storage.file.models.File(name='remote/name')
    patched_cisf.return_value = (False, None)
    patched_lf.side_effect = [[f]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    # test normal subdir path
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('remote/name')
        assert file.encryption_metadata is None
    assert i == 1

    # test no container list perm
    sa.can_list_container_objects = False
    patched_gfp.side_effect = [f]
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('remote/name')
        assert file.encryption_metadata is None
    assert i == 1

    # test no container list perm, nonexistent
    patched_gfp.side_effect = [None]
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
    assert i == 0

    # test no container list perm, filter dry run
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_cisf.return_value = (True, f)
    patched_gfp.side_effect = [f]
    assert len(list(asp.files(creds, options, True))) == 0

    # test no container list perm, no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_gfp.side_effect = [f]
        assert len(list(asp.files(creds, options, False))) == 0

    sa.can_list_container_objects = True

    # test filter
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_cisf.return_value = (True, f)
    patched_lf.side_effect = [[f]]
    assert len(list(asp.files(creds, options, True))) == 0

    # test no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_lf.side_effect = [[f]]
        assert len(list(asp.files(creds, options, False))) == 0

    # test encrypted
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    fe = azure.storage.file.models.File(name='remote/name')
    fe.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lf.side_effect = [[fe]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, True):
        i += 1
        assert pathlib.Path(file.name) == pathlib.Path('remote/name')
        assert file.encryption_metadata is not None
    assert i == 1


@mock.patch('blobxfer.models.crypto.EncryptionMetadata')
@mock.patch('blobxfer.operations.azure.blob.list_blobs')
@mock.patch('blobxfer.operations.azure.blob.get_blob_properties')
def test_azuresourcepath_blobs(patched_gbp, patched_lb, patched_em):
    p = '/cont/remote/path'
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = azmodels.StorageModes.Auto
    creds = mock.MagicMock()
    sa = mock.MagicMock()
    sa.block_blob_client = mock.MagicMock()
    creds.get_storage_account.return_value = sa
    b = azure.storage.blob.models.Blob(name='name')
    b.metadata = {}
    patched_lb.side_effect = [[b]]
    patched_em.encryption_metadata_exists = mock.MagicMock()
    patched_em.encryption_metadata_exists.return_value = False

    # test no read access
    sa.can_read_object = False
    with pytest.raises(RuntimeError):
        next(asp.files(creds, options, False))
    sa.can_read_object = True

    # test normal path
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    # test normal path with metadata vdir sep
    b.metadata[azops._METADATA_VIRTUAL_DIRECTORY] = 'true'
    patched_lb.side_effect = [[b]]
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
    assert i == 0

    b.metadata = {}

    # test no container list perm
    sa.can_list_container_objects = False
    patched_gbp.side_effect = [b]
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    # test no container list perm, nonexistent
    patched_gbp.side_effect = [None]
    i = 0
    for file in asp.files(creds, options, False):
        i += 1
    assert i == 0

    # test no container list perm, filter dry run
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_gbp.side_effect = [b]
    assert len(list(asp.files(creds, options, True))) == 0

    # test no container list perm, no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_gbp.side_effect = [b]
        assert len(list(asp.files(creds, options, False))) == 0

    sa.can_list_container_objects = True

    # test filter
    asp = azops.SourcePath()
    asp.add_path_with_storage_account(p, 'sa')
    asp.add_includes(['zzz'])
    patched_lb.side_effect = [[b]]
    assert len(list(asp.files(creds, options, True))) == 0

    # test no vio return
    with mock.patch(
            'blobxfer.operations.azure.SourcePath.'
            '_handle_vectored_io_stripe') as patched_hvios:
        patched_hvios.side_effect = [[None]]
        asp = azops.SourcePath()
        asp.add_path_with_storage_account(p, 'sa')
        patched_lb.side_effect = [[b]]
        assert len(list(asp.files(creds, options, False))) == 0

    be = azure.storage.blob.models.Blob(name='name')
    be.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lb.side_effect = [[be]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, False):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1


def test_azuresourcepath_url():
    asp = azops.SourcePath()
    asp.add_arbitrary_remote_url('https://host/remote/path')
    asp._populate_from_arbitrary_url = mock.MagicMock()

    sc = blobxfer.models.options.SyncCopy(
        access_tier=None,
        delete_extraneous_destination=None,
        delete_only=None,
        dest_mode=None,
        mode=None,
        overwrite=None,
        recursive=None,
        rename=None,
        server_side_copy=True,
        strip_components=0,
    )

    i = 0
    for ase in asp._populate_from_list_blobs(mock.MagicMock(), sc, False):
        i += 1

    assert asp._populate_from_arbitrary_url.call_count == 1
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
