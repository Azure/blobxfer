# coding=utf-8
"""Tests for models"""

# stdlib imports
import os
try:
    import pathlib2 as pathlib
except ImportError:
    import pathlib
# non-stdlib imports
import azure.storage
import pytest
# module under test
import blobxfer.models


def test_storage_credentials():
    creds = blobxfer.models.AzureStorageCredentials()
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
    a = blobxfer.models.AzureStorageAccount('name', 'abcdef', 'endpoint')
    assert not a.is_sas

    a = blobxfer.models.AzureStorageAccount('name', 'abcdef&blah', 'endpoint')
    assert not a.is_sas

    a = blobxfer.models.AzureStorageAccount('name', '?abcdef', 'endpoint')
    assert a.is_sas

    a = blobxfer.models.AzureStorageAccount(
        'name', '?sv=0&sr=1&sig=2', 'endpoint')
    assert a.is_sas

    a = blobxfer.models.AzureStorageAccount(
        'name', 'sv=0&sr=1&sig=2', 'endpoint')
    assert a.is_sas

    a = blobxfer.models.AzureStorageAccount(
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

    a = blobxfer.models.LocalSourcePaths()
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

    b = blobxfer.models.LocalSourcePaths()
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

    a = blobxfer.models.LocalDestinationPath(str(path))
    a.is_dir = True
    assert str(a.path) == str(path)
    assert a.is_dir

    a.ensure_path_exists()
    assert os.path.exists(str(a.path))

    b = blobxfer.models.LocalDestinationPath()
    b.is_dir = False
    b.path = str(path)
    with pytest.raises(RuntimeError):
        b.ensure_path_exists()
    assert not b.is_dir

    path2 = tmpdir.join('2')
    path3 = path2.join('3')
    c = blobxfer.models.LocalDestinationPath(str(path3))
    with pytest.raises(RuntimeError):
        c.ensure_path_exists()
    c.is_dir = False
    c.ensure_path_exists()
    assert os.path.exists(str(path2))
    assert os.path.isdir(str(path2))
    assert not c.is_dir


def test_azuresourcepath():
    p = '/cont/remote/path'
    asp = blobxfer.models.AzureSourcePath()
    asp.add_path_with_storage_account(p, 'sa')

    with pytest.raises(RuntimeError):
        asp.add_path_with_storage_account('x', 'x')

    assert 'sa' == asp.lookup_storage_account(p)


def test_downloadspecification():
    ds = blobxfer.models.DownloadSpecification(
        download_options=blobxfer.models.DownloadOptions(
            check_file_md5=True,
            delete_extraneous_destination=False,
            mode=blobxfer.models.AzureStorageModes.Auto,
            overwrite=True,
            recursive=True,
            restore_file_attributes=False,
            rsa_private_key=None,
            rsa_private_key_passphrase=None,
        ),
        skip_on_options=blobxfer.models.SkipOnOptions(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        ),
        local_destination_path=blobxfer.models.LocalDestinationPath('dest'),
    )

    asp = blobxfer.models.AzureSourcePath()
    p = 'some/remote/path'
    asp.add_path_with_storage_account(p, 'sa')

    ds.add_azure_source_path(asp)

    assert ds.options.check_file_md5
    assert not ds.skip_on.lmt_ge
    assert ds.destination.path == pathlib.Path('dest')
    assert len(ds.sources) == 1
    assert p in ds.sources[0]._path_map
    assert ds.sources[0]._path_map[p] == 'sa'
