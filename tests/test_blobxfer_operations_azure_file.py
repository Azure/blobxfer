# coding=utf-8
"""Tests for file operations"""

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
import azure.common
import azure.storage.common
# local imports
import blobxfer.util as util
import blobxfer.version
# module under test
import blobxfer.operations.azure as azops
import blobxfer.operations.azure.file as ops


def test_create_client():
    sa = azops.StorageAccount(
        'name', 'key', 'core.windows.net', 10, mock.MagicMock(),
        mock.MagicMock())
    client = ops.create_client(sa, mock.MagicMock(), mock.MagicMock())
    assert client is not None
    assert isinstance(client, azure.storage.file.FileService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSharedKeyAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
    assert client._httpclient.proxies is not None

    sa = azops.StorageAccount(
        'name', '?key&sig=key', 'core.windows.net', 10, mock.MagicMock(), None)
    client = ops.create_client(sa, mock.MagicMock(), None)
    assert client is not None
    assert isinstance(client, azure.storage.file.FileService)
    assert isinstance(
        client.authentication,
        azure.storage.common._auth._StorageSASAuthentication)
    assert client._USER_AGENT_STRING.startswith(
        'blobxfer/{}'.format(blobxfer.version.__version__))
    assert client._httpclient.proxies is None


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
    for file in ops.list_files(client, 'a', 'b/c', True):
        i += 1
        assert file == 'fp'
    assert i == 1


def test_list_all_files():
    client = mock.MagicMock()
    client.list_directories_and_files.side_effect = [
        [
            azure.storage.file.models.Directory(name='dir'),
        ],
        [
            azure.storage.file.models.File(name='a'),
        ],
    ]

    i = 0
    for f in ops.list_all_files(client, 'fshare'):
        assert pathlib.Path(f) == pathlib.Path('dir/a')
        i += 1
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
    for file in ops.list_files(client, 'dir', '', True):
        i += 1
        assert file.name == 'name'
    assert i == 1

    _dir = azure.storage.file.models.Directory(name='dirname')
    _file = azure.storage.file.models.File(name='dirname/name')
    client = mock.MagicMock()
    client.list_directories_and_files.side_effect = [[_dir, _file]]
    client.get_file_properties.side_effect = [_file]

    i = 0
    for file in ops.list_files(client, '', '', True):
        i += 1
        assert file.name == _file.name
        assert type(file) == azure.storage.file.models.File
    assert i == 1


def test_delete_file():
    assert ops.delete_file(mock.MagicMock(), 'fshare', 'dir/name') is None


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


def test_create_share():
    ase = mock.MagicMock()
    ase.create_containers = False

    ops.create_share(ase, None)
    assert ase.client.create_share.call_count == 0

    ase.create_containers = True
    ase.client.account_name = 'sa'
    ase.container = 'cont'

    cc = set()
    ase.client.create_shuare.return_value = True
    ops.create_share(ase, cc)
    assert len(cc) == 1

    ase.client.create_shuare.return_value = False
    ops.create_share(ase, cc)
    assert len(cc) == 1

    ase.container = 'cont2'
    ops.create_share(ase, cc)
    assert len(cc) == 2

    ops.create_share(ase, cc)
    assert len(cc) == 2


def test_create_all_parent_directories():
    ase = mock.MagicMock()
    ase.client.account_name = 'sa'
    ase.container = 'cont'
    ase.name = 'abc'

    dirs = {}
    ops.create_all_parent_directories(ase, dirs)
    assert len(dirs) == 0

    ase.name = 'a/b/c.bin'
    ops.create_all_parent_directories(ase, dirs)
    assert len(dirs) == 1
    assert len(dirs['sa:cont']) == 2


def test_create_file():
    ase = mock.MagicMock()
    ase.name = 'a/b/c.bin'
    assert ops.create_file(ase) is None


def test_put_file_range():
    ase = mock.MagicMock()
    ase.name = 'a/b/c.bin'
    assert ops.put_file_range(ase, mock.MagicMock(), b'\0') is None


def test_set_file_md5():
    ase = mock.MagicMock()
    ase.name = 'a/b/c.bin'
    assert ops.set_file_md5(ase, 'md5') is None


def test_set_file_metadata():
    ase = mock.MagicMock()
    ase.name = 'a/b/c.bin'
    assert ops.set_file_metadata(ase, 'md') is None
