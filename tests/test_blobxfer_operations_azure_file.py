# coding=utf-8
"""Tests for file operations"""

# stdlib imports
import mock
# non-stdlib imports
import azure.common
import azure.storage
# local imports
import blobxfer.util as util
# module under test
import blobxfer.operations.azure as azops
import blobxfer.operations.azure.file as ops


def test_create_client():
    sa = azops.StorageAccount('name', 'key', 'endpoint')
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.file.FileService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSharedKeyAuthentication)

    sa = azops.StorageAccount('name', '?key&sig=key', 'endpoint')
    client = ops.create_client(sa)
    assert client is not None
    assert isinstance(client, azure.storage.file.FileService)
    assert isinstance(
        client.authentication,
        azure.storage._auth._StorageSASAuthentication)


def test_parse_file_path():
    rpath = '/a/b/c'
    fshare, path = util.explode_azure_path(util.normalize_azure_path(rpath))
    dir, fname = ops.parse_file_path(path)
    assert fshare == 'a'
    assert dir == 'b'
    assert fname == 'c'

    rpath = 'a/b/c/d'
    fshare, path = util.explode_azure_path(util.normalize_azure_path(rpath))
    dir, fname = ops.parse_file_path(path)
    assert fshare == 'a'
    assert dir == 'b/c'
    assert fname == 'd'

    rpath = 'a/b'
    fshare, path = util.explode_azure_path(util.normalize_azure_path(rpath))
    dir, fname = ops.parse_file_path(path)
    assert fshare == 'a'
    assert dir is None
    assert fname == 'b'

    rpath = 'a'
    fshare, path = util.explode_azure_path(util.normalize_azure_path(rpath))
    dir, fname = ops.parse_file_path(path)
    assert fshare == 'a'
    assert dir is None
    assert fname is None


def test_check_if_single_file():
    client = mock.MagicMock()
    client.get_file_properties = mock.MagicMock()
    client.get_file_properties.return_value = mock.MagicMock()

    result = ops.check_if_single_file(client, 'a', 'b/c')
    assert result[0]

    result = ops.check_if_single_file(client, 'a', '')
    assert not result[0]

    client = mock.MagicMock()
    client.get_file_properties = mock.MagicMock()
    client.get_file_properties.side_effect = \
        azure.common.AzureMissingResourceHttpError('msg', 404)

    result = ops.check_if_single_file(client, 'a', 'b/c')
    assert not result[0]


def test_list_files_single_file():
    client = mock.MagicMock()
    client.get_file_properties = mock.MagicMock()
    client.get_file_properties.return_value = 'fp'

    i = 0
    for file in ops.list_files(client, 'a', 'b/c'):
        i += 1
        assert file == 'fp'
    assert i == 1


@mock.patch(
    'blobxfer.operations.azure.file.check_if_single_file',
    return_value=(False, None)
)
def test_list_files_directory(patched_cisf):
    _file = azure.storage.file.models.File(name='name')
    client = mock.MagicMock()
    client.list_directories_and_files.return_value = [_file]
    client.get_file_properties.return_value = _file

    i = 0
    for file in ops.list_files(client, 'dir', ''):
        i += 1
        assert file.name == 'name'
    assert i == 1

    print('test')
    _dir = azure.storage.file.models.Directory(name='dirname')
    _file = azure.storage.file.models.File(name='dirname/name')
    client = mock.MagicMock()
    client.list_directories_and_files.side_effect = [[_dir, _file]]
    client.get_file_properties.side_effect = [_file]

    i = 0
    for file in ops.list_files(client, '', ''):
        i += 1
        assert file.name == _file.name
        assert type(file) == azure.storage.file.models.File
    assert i == 1


def test_get_file_range():
    ase = mock.MagicMock()
    ret = mock.MagicMock()
    ret.content = b'\0'
    ase.client._get_file.return_value = ret
    ase.container = 'cont'
    ase.name = 'name'
    offsets = mock.MagicMock()
    offsets.start_range = 0
    offsets.end_range = 1

    assert ops.get_file_range(ase, offsets) == ret.content
