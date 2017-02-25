# coding=utf-8
"""Tests for models"""

# stdlib imports
import mock
import os
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import azure.storage
import azure.storage.blob
import azure.storage.file
import pytest
# module under test
import blobxfer.models as models


@mock.patch('multiprocessing.cpu_count', return_value=1)
def test_concurrency_options(patched_cc):
    a = models.ConcurrencyOptions(
        crypto_processes=-1,
        md5_processes=0,
        transfer_threads=-2,
    )

    assert a.crypto_processes == 1
    assert a.md5_processes == 1
    assert a.transfer_threads == 2


def test_general_options():
    a = models.GeneralOptions(
        concurrency=models.ConcurrencyOptions(
            crypto_processes=1,
            md5_processes=2,
            transfer_threads=3,
        ),
        progress_bar=False,
        timeout_sec=1,
        verbose=True,
    )

    assert a.concurrency.crypto_processes == 1
    assert a.concurrency.md5_processes == 2
    assert a.concurrency.transfer_threads == 3
    assert not a.progress_bar
    assert a.timeout_sec == 1
    assert a.verbose

    with pytest.raises(ValueError):
        a = models.GeneralOptions(None)


def test_storage_credentials():
    creds = models.AzureStorageCredentials()
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
    a = models.AzureStorageAccount('name', 'abcdef', 'endpoint')
    assert not a.is_sas

    a = models.AzureStorageAccount('name', 'abcdef&blah', 'endpoint')
    assert not a.is_sas

    a = models.AzureStorageAccount('name', '?abcdef', 'endpoint')
    assert a.is_sas

    a = models.AzureStorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'endpoint')
    assert a.is_sas

    a = models.AzureStorageAccount(
        'name', 'sv=0&sr=1&sig=2', 'endpoint')
    assert a.is_sas

    a = models.AzureStorageAccount(
        'name', 'sig=0&sv=0&sr=1&se=2', 'endpoint')
    assert a.is_sas


def test_localsourcepaths_files(tmpdir):
    tmpdir.mkdir('abc')
    tmpdir.join('moo.cow').write('z')
    abcpath = tmpdir.join('abc')
    abcpath.join('hello.txt').write('hello')
    abcpath.join('blah.x').write('x')
    abcpath.join('blah.y').write('x')
    abcpath.join('blah.z').write('x')
    abcpath.mkdir('def')
    defpath = abcpath.join('def')
    defpath.join('world.txt').write('world')
    defpath.join('moo.cow').write('y')

    a = models.LocalSourcePaths()
    a.add_include('*.txt')
    a.add_includes(['moo.cow', '*blah*'])
    with pytest.raises(ValueError):
        a.add_includes('abc')
    a.add_exclude('**/blah.x')
    a.add_excludes(['world.txt'])
    with pytest.raises(ValueError):
        a.add_excludes('abc')
    a.add_path(str(tmpdir))
    a_set = set()
    for file in a.files():
        sfile = str(file.parent_path / file.relative_path)
        a_set.add(sfile)

    assert len(a.paths) == 1
    assert str(abcpath.join('blah.x')) not in a_set
    assert str(defpath.join('world.txt')) in a_set
    assert str(defpath.join('moo.cow')) not in a_set

    b = models.LocalSourcePaths()
    b.add_includes(['moo.cow', '*blah*'])
    b.add_include('*.txt')
    b.add_excludes(['world.txt'])
    b.add_exclude('**/blah.x')
    b.add_paths([pathlib.Path(str(tmpdir))])
    for file in a.files():
        sfile = str(file.parent_path / file.relative_path)
        assert sfile in a_set


def test_localdestinationpath(tmpdir):
    tmpdir.mkdir('1')
    path = tmpdir.join('1')

    a = models.LocalDestinationPath(str(path))
    a.is_dir = True
    assert str(a.path) == str(path)
    assert a.is_dir

    a.ensure_path_exists()
    assert os.path.exists(str(a.path))

    b = models.LocalDestinationPath()
    b.is_dir = False
    b.path = str(path)
    with pytest.raises(RuntimeError):
        b.ensure_path_exists()
    assert not b.is_dir

    path2 = tmpdir.join('2')
    path3 = path2.join('3')
    c = models.LocalDestinationPath(str(path3))
    with pytest.raises(RuntimeError):
        c.ensure_path_exists()
    c.is_dir = False
    c.ensure_path_exists()
    assert os.path.exists(str(path2))
    assert os.path.isdir(str(path2))
    assert not c.is_dir


def test_azuresourcepath():
    p = '/cont/remote/path'
    asp = models.AzureSourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    with pytest.raises(RuntimeError):
        asp.add_path_with_storage_account('x', 'x')

    assert 'sa' == asp.lookup_storage_account(p)


@mock.patch('blobxfer.crypto.models.EncryptionMetadata')
@mock.patch('blobxfer.file.operations.list_files')
def test_azuresourcepath_files(patched_lf, patched_em):
    p = '/cont/remote/path'
    asp = models.AzureSourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = models.AzureStorageModes.File
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
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    fe = azure.storage.file.models.File(name='name')
    fe.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lf.side_effect = [[fe]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1


@mock.patch('blobxfer.crypto.models.EncryptionMetadata')
@mock.patch('blobxfer.blob.operations.list_blobs')
def test_azuresourcepath_blobs(patched_lb, patched_em):
    p = '/cont/remote/path'
    asp = models.AzureSourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    options = mock.MagicMock()
    options.mode = models.AzureStorageModes.Auto
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
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is None
    assert i == 1

    be = azure.storage.blob.models.Blob(name='name')
    be.metadata = {'encryptiondata': {'a': 'b'}}
    patched_lb.side_effect = [[be]]
    patched_em.encryption_metadata_exists.return_value = True
    patched_em.convert_from_json = mock.MagicMock()

    i = 0
    for file in asp.files(creds, options, mock.MagicMock()):
        i += 1
        assert file.name == 'name'
        assert file.encryption_metadata is not None
    assert i == 1


def test_downloadspecification():
    ds = models.DownloadSpecification(
        download_options=models.DownloadOptions(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
        ),
        skip_on_options=models.SkipOnOptions(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        ),
        local_destination_path=models.LocalDestinationPath('dest'),
    )

    asp = models.AzureSourcePath()
    p = 'some/remote/path'
    asp.add_path_with_storage_account(p, 'sa')

    ds.add_azure_source_path(asp)

    assert ds.options.check_file_md5
    assert not ds.skip_on.lmt_ge
    assert ds.destination.path == pathlib.Path('dest')
    assert len(ds.sources) == 1
    assert p in ds.sources[0]._path_map
    assert ds.sources[0]._path_map[p] == 'sa'


def test_azurestorageentity():
    ase = models.AzureStorageEntity('cont')
    assert ase.container == 'cont'
    assert ase.encryption_metadata is None

    blob = mock.MagicMock()
    blob.name = 'name'
    blob.snapshot = None
    blob.properties = mock.MagicMock()
    blob.properties.last_modified = 'lmt'
    blob.properties.content_length = 123
    blob.properties.content_settings = mock.MagicMock()
    blob.properties.content_settings.content_md5 = 'abc'
    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.BlockBlob
    ase.populate_from_blob(mock.MagicMock(), blob)

    assert ase.client is not None
    assert ase.name == 'name'
    assert ase.lmt == 'lmt'
    assert ase.size == 123
    assert ase.md5 == 'abc'
    assert ase.snapshot is None
    assert ase.mode == models.AzureStorageModes.Block

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.AppendBlob
    ase.populate_from_blob(mock.MagicMock(), blob)
    assert ase.mode == models.AzureStorageModes.Append

    blob.properties.blob_type = azure.storage.blob.models._BlobTypes.PageBlob
    blob.snapshot = 'abc'
    ase.populate_from_blob(mock.MagicMock(), blob)
    assert ase.mode == models.AzureStorageModes.Page
    assert ase.snapshot is not None

    blob.snapshot = None
    ase.populate_from_file(mock.MagicMock(), blob)
    assert ase.mode == models.AzureStorageModes.File
    assert ase.snapshot is None


def test_downloaddescriptor(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 16
    ase = models.AzureStorageEntity('cont')
    ase._size = 1024
    ase._encryption = mock.MagicMock()
    d = models.DownloadDescriptor(lp, ase, opts)

    assert d.entity == ase
    assert not d.must_compute_md5
    assert d._total_chunks == 64
    assert d.offset == 0
    assert d.final_path == lp
    assert str(d.local_path) == str(lp) + '.bxtmp'
    assert d.local_path.stat().st_size == 1024 - 16

    d.local_path.unlink()
    ase._size = 1
    d = models.DownloadDescriptor(lp, ase, opts)
    assert d._total_chunks == 1
    assert d.local_path.stat().st_size == 0

    d.local_path.unlink()
    ase._encryption = None
    ase._size = 1024
    d = models.DownloadDescriptor(lp, ase, opts)
    assert d.local_path.stat().st_size == 1024

    # pre-existing file check
    ase._size = 0
    d = models.DownloadDescriptor(lp, ase, opts)
    assert d._total_chunks == 0
    assert d.local_path.stat().st_size == 0


def test_downloaddescriptor_next_offsets(tmpdir):
    lp = pathlib.Path(str(tmpdir.join('a')))

    opts = mock.MagicMock()
    opts.check_file_md5 = True
    opts.chunk_size_bytes = 256
    ase = models.AzureStorageEntity('cont')
    ase._size = 128
    d = models.DownloadDescriptor(lp, ase, opts)

    offsets = d.next_offsets()
    assert d._total_chunks == 1
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 128
    assert offsets.range_start == 0
    assert offsets.range_end == 127
    assert not offsets.unpad
    assert d.next_offsets() is None

    ase._size = 0
    d = models.DownloadDescriptor(lp, ase, opts)
    assert d._total_chunks == 0
    assert d.next_offsets() is None

    ase._size = 1
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 1
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 1
    assert offsets.range_start == 0
    assert offsets.range_end == 0
    assert not offsets.unpad
    assert d.next_offsets() is None

    ase._size = 256
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 1
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    assert d.next_offsets() is None

    ase._size = 256 + 16
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 2
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    offsets = d.next_offsets()
    assert offsets.fd_start == 256
    assert offsets.num_bytes == 16
    assert offsets.range_start == 256
    assert offsets.range_end == 256 + 15
    assert not offsets.unpad
    assert d.next_offsets() is None

    ase._encryption = mock.MagicMock()
    ase._size = 128
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 1
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 128
    assert offsets.range_start == 0
    assert offsets.range_end == 127
    assert offsets.unpad
    assert d.next_offsets() is None

    ase._size = 256
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 1
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert offsets.unpad
    assert d.next_offsets() is None

    ase._size = 256 + 32  # 16 bytes over + padding
    d = models.DownloadDescriptor(lp, ase, opts)
    offsets = d.next_offsets()
    assert d._total_chunks == 2
    assert offsets.fd_start == 0
    assert offsets.num_bytes == 256
    assert offsets.range_start == 0
    assert offsets.range_end == 255
    assert not offsets.unpad
    offsets = d.next_offsets()
    assert offsets.fd_start == 256
    assert offsets.num_bytes == 32
    assert offsets.range_start == 256 - 16
    assert offsets.range_end == 256 + 31
    assert offsets.unpad
    assert d.next_offsets() is None
