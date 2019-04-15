# coding=utf-8
"""Tests for models upload"""

# stdlib imports
import hashlib
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import bitstring
import pytest
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.metadata as metadata
import blobxfer.models.options as options
import blobxfer.operations.azure as azops
import blobxfer.util as util
# module under test
import blobxfer.models.upload as upload


def test_vectorediodistributionmode():
    a = upload.VectoredIoDistributionMode('stripe')
    assert a == upload.VectoredIoDistributionMode.Stripe
    assert str(a) == 'stripe'


def test_localpath(tmpdir):
    tmpdir.join('a').write('zz')
    pp = pathlib.Path(str(tmpdir))
    rp = pathlib.Path('a')
    file = pp / rp
    stat = file.stat()

    lp = upload.LocalPath(pp, rp, use_stdin=True, view=None)
    assert lp.absolute_path == file
    assert lp.size == 0
    assert lp.total_size == 0
    assert lp.lmt == 0
    assert lp.mode.replace('o', '') == '00'
    assert lp.uid == 0
    assert lp.gid == 0

    lp = upload.LocalPath(pp, rp, use_stdin=False, view=None)
    assert lp.absolute_path == file
    assert lp.size == stat.st_size
    assert lp.total_size == stat.st_size
    assert lp.lmt == stat.st_mtime
    assert lp.mode.replace('o', '') == str(oct(stat.st_mode)).replace('o', '')
    assert lp.uid == stat.st_uid
    assert lp.gid == stat.st_gid

    lpview = upload.LocalPathView(
        fd_start=1,
        fd_end=2,
        slice_num=1,
        mode=upload.VectoredIoDistributionMode.Stripe,
        total_slices=2,
        next=None,
    )
    lp = upload.LocalPath(pp, rp, use_stdin=False, view=lpview)
    assert lp.absolute_path == file
    assert lp.size == 1
    assert lp.total_size == stat.st_size
    assert lp.lmt == stat.st_mtime
    assert lp.mode.replace('o', '') == str(oct(stat.st_mode)).replace('o', '')
    assert lp.uid == stat.st_uid
    assert lp.gid == stat.st_gid


def _resolve_pypath(path):
    return str(pathlib.Path(str(path)).resolve())


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

    a = upload.LocalSourcePath()
    a.add_includes('**')
    a.add_includes('*.txt')
    a.add_includes(('moo.cow', '*blah*'))
    with pytest.raises(ValueError):
        a.add_includes('**/**/*')
    a.add_excludes('**')
    a.add_excludes('**/blah.x')
    with pytest.raises(ValueError):
        a.add_excludes('**/**/blah.x')
    a.add_excludes(['world.txt'])
    a.add_path(str(tmpdir))
    a_set = set()
    for file in a.files(True):
        sfile = str(file.parent_path / file.relative_path)
        a_set.add(sfile)

    assert len(a._include) == 3
    assert len(a._exclude) == 2

    assert not a.can_rename()
    assert len(a.paths) == 1
    assert _resolve_pypath(abcpath.join('blah.x')) in a_set
    assert _resolve_pypath(defpath.join('world.txt')) in a_set
    assert _resolve_pypath(defpath.join('moo.cow')) not in a_set

    b = upload.LocalSourcePath()
    b.add_includes(['moo.cow', '*blah*'])
    b.add_includes('*.txt')
    b.add_excludes(('world.txt',))
    b.add_excludes('**/blah.x')
    b.add_paths([pathlib.Path(str(tmpdir))])
    for file in a.files(True):
        sfile = str(file.parent_path / file.relative_path)
        assert sfile in a_set

    assert upload.LocalSourcePath.is_stdin('-')
    assert upload.LocalSourcePath.is_stdin('/dev/stdin')
    assert not upload.LocalSourcePath.is_stdin('/')

    a = upload.LocalSourcePath()
    a.add_includes('z')
    a.add_path(str(tmpdir) + '/abc/hello.txt')
    a_set = set()
    for file in a.files(True):
        sfile = str(file.parent_path / file.relative_path)
        a_set.add(sfile)
    assert len(a_set) == 0

    c = upload.LocalSourcePath()
    c.add_path('-')
    for file in c.files(False):
        assert file.use_stdin

    d = upload.LocalSourcePath()
    d.add_path(str(tmpdir.join('moo.cow')))
    i = 0
    for file in d.files(True):
        assert str(file.parent_path.absolute()) == str(tmpdir)
        assert str(file.relative_path) == 'moo.cow'
        assert not file.use_stdin
        i += 1
    assert i == 1

    tmpdir.join('moo.cow2').ensure(file=True)
    d.add_path(str(tmpdir.join('moo.cow2')))
    i = 0
    for file in d.files(True):
        i += 1
    assert i == 2


def test_specification(tmpdir):
    lsp = upload.LocalSourcePath()
    lsp.add_paths(['-', '/dev/stdin'])
    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=4194304,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=0,
                overwrite=True,
                recursive=True,
                rename=True,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control='cc',
                    content_type='ct',
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    lsp = upload.LocalSourcePath()
    lsp.add_path(str(tmpdir))
    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=4194304,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=0,
                overwrite=True,
                recursive=True,
                rename=True,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control='cc',
                    content_type='ct',
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    lsp = upload.LocalSourcePath()
    lsp.add_path(str(tmpdir))
    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=-1,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=0,
                overwrite=True,
                recursive=True,
                rename=False,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control='cc',
                    content_type='ct',
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES + 1,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=0,
                overwrite=True,
                recursive=True,
                rename=False,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control='cc',
                    content_type='ct',
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=4194304,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=-1,
                overwrite=True,
                recursive=True,
                rename=False,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control='cc',
                    content_type='ct',
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    with pytest.raises(ValueError):
        upload.Specification(
            upload_options=options.Upload(
                access_tier=None,
                chunk_size_bytes=4194304,
                delete_extraneous_destination=False,
                mode=azmodels.StorageModes.Auto,
                one_shot_bytes=upload._MAX_BLOCK_BLOB_ONESHOT_BYTES + 1,
                overwrite=True,
                recursive=True,
                rename=False,
                rsa_public_key=None,
                stdin_as_page_blob_size=0,
                store_file_properties=options.FileProperties(
                    attributes=True,
                    cache_control=None,
                    content_type=None,
                    lmt=None,
                    md5=True,
                ),
                strip_components=0,
                vectored_io=None,
            ),
            skip_on_options=options.SkipOn(
                filesize_match=True,
                lmt_ge=False,
                md5_match=True,
            ),
            local_source_path=lsp,
        )

    spec = upload.Specification(
        upload_options=options.Upload(
            access_tier=None,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            mode=azmodels.StorageModes.Auto,
            one_shot_bytes=0,
            overwrite=True,
            recursive=True,
            rename=False,
            rsa_public_key=None,
            stdin_as_page_blob_size=0,
            store_file_properties=options.FileProperties(
                attributes=True,
                cache_control=None,
                content_type=None,
                lmt=None,
                md5=True,
            ),
            strip_components=0,
            vectored_io=None,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        ),
        local_source_path=lsp,
    )
    spec.add_azure_destination_path(azops.DestinationPath())
    assert len(spec.destinations) == 1


def test_descriptor(tmpdir):
    size = 32
    tmpdir.join('a').write('z' * size)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 8
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = False
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._size = size
    ase._encryption = None
    ase2 = azmodels.StorageEntity('cont')
    ase2._mode = azmodels.StorageModes.Block
    ase2._name = 'name2'
    ase2._size = size
    ase2._encryption = None
    ase.replica_targets = [ase2]

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())

    assert ud.hmac is None
    assert ud.md5 is None
    assert ud._outstanding_ops == 4 * 2
    assert ud._completed_chunks is not None
    assert ud._md5_cache is not None
    assert ud._replica_counters is not None
    assert ud.entity == ase
    assert not ud.must_compute_md5
    assert not ud.all_operations_completed
    assert ud.last_block_num == -1
    assert ud.is_resumable
    assert not ud.remote_is_file
    assert not ud.remote_is_page_blob
    assert not ud.remote_is_append_blob
    assert not ud.is_one_shot_block_blob
    assert ud.requires_put_block_list
    assert not ud.requires_non_encrypted_md5_put
    assert not ud.requires_set_file_properties_md5
    assert not ud.requires_access_tier_set
    assert ud.requires_resize() == (False, ud._offset)

    # test sym key
    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._size = size
    ase._encryption = mock.MagicMock()
    opts.rsa_public_key = None
    with pytest.raises(RuntimeError):
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())


def test_descriptor_complete_offset_upload(tmpdir):
    tmpdir.join('a').write('z' * 32)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 16
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._size = 32
    ase._encryption = None
    ase.replica_targets = [ase]

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())

    ud._md5_cache[0] = 'md50'
    ud._md5_cache[1] = 'md51'

    ud.complete_offset_upload(0)
    assert ud._outstanding_ops == 3
    assert ud._replica_counters[0] == 0
    ud.complete_offset_upload(1)
    assert ud._outstanding_ops == 2
    assert ud._replica_counters[1] == 0

    # fill md5 cache with junk to trigger gc on next complete
    for i in range(-30, -1):
        ud._md5_cache[i] = ''

    ud.complete_offset_upload(0)
    assert ud._outstanding_ops == 1
    assert 0 not in ud._replica_counters
    assert len(ud._md5_cache) == 2

    ud.complete_offset_upload(1)
    assert ud._outstanding_ops == 0
    assert 1 not in ud._replica_counters
    assert len(ud._md5_cache) == 0


def test_descriptor_hmac_data(tmpdir):
    tmpdir.join('a').write('z' * 32)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 16
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._size = 32
    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = 'abc'
    ase.replica_targets = [ase]

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud.hmac is not None
    ud.hmac_data(b'\0')


def test_descriptor_initialize_encryption(tmpdir):
    tmpdir.join('a').write('z' * 32)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 16
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = 'abc'

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._size = 32

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud.hmac is not None
    assert ud.entity.is_encrypted


def test_descriptor_compute_remote_size(tmpdir):
    tmpdir.join('a').write('z' * 32)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    # encrypted remote size with replica
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 16
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = 'abc'

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = mock.MagicMock()
    ase._encryption.symmetric_key = 'abc'
    ase2 = azmodels.StorageEntity('cont')
    ase2._mode = azmodels.StorageModes.Block
    ase2._name = 'name2'
    ase.replica_targets = [ase2]

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._compute_remote_size(opts)
    assert ud.entity.size == 48
    for rt in ase.replica_targets:
        assert rt.size == ud.entity.size

    # remote size
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 16
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._compute_remote_size(opts)
    assert ud.entity.size == 32

    # remote size of zero
    tmpdir.join('b').ensure(file=True)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('b'))

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._compute_remote_size(opts)
    assert ud.entity.size == 0

    # stdin as page, resize
    lp = upload.LocalPath(pathlib.Path('-'), pathlib.Path('-'), use_stdin=True)
    opts.stdin_as_page_blob_size = 0
    ase._mode = azmodels.StorageModes.Page
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._compute_remote_size(opts)
    assert ud.entity.size == upload._MAX_PAGE_BLOB_SIZE
    assert ud._needs_resize

    # stdin as page, no resize
    lp = upload.LocalPath(pathlib.Path('-'), pathlib.Path('-'), use_stdin=True)
    opts.stdin_as_page_blob_size = 32
    ase._mode = azmodels.StorageModes.Page
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._compute_remote_size(opts)
    assert ud.entity.size == 32
    assert not ud._needs_resize


def test_descriptor_adjust_chunk_size(tmpdir):
    tmpdir.join('a').ensure(file=True)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 0
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud._chunk_size == 0

    with mock.patch('blobxfer.models.upload._DEFAULT_AUTO_CHUNKSIZE_BYTES', 1):
        with mock.patch(
                'blobxfer.models.upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES', 3):
            with mock.patch('blobxfer.models.upload._MAX_NUM_CHUNKS', 2):
                tmpdir.join('a').write('z' * 4)
                lp = upload.LocalPath(
                    pathlib.Path(str(tmpdir)), pathlib.Path('a'))
                ud = upload.Descriptor(
                    lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
                assert ud._chunk_size == 2

    lp = upload.LocalPath(
        pathlib.Path(str(tmpdir)), pathlib.Path('-'), use_stdin=True)
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud._chunk_size == upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES

    tmpdir.join('a').write('z' * 32)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Page
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud._chunk_size == 32

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Append
    ase._name = 'name'
    ase._encryption = None

    opts.chunk_size_bytes = upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES + 1
    with mock.patch(
            'blobxfer.models.upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES', 4):
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
        assert ud._chunk_size == 4

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    opts.chunk_size_bytes = 32
    opts.one_shot_bytes = 32
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    assert ud._chunk_size == 32

    opts.one_shot_bytes = 31
    with mock.patch(
            'blobxfer.models.upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES', 4):
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
        assert ud._chunk_size == 4

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.File
    ase._name = 'name'
    ase._encryption = None

    opts.chunk_size_bytes = upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES + 1
    with mock.patch(
            'blobxfer.models.upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES', 4):
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
        assert ud._chunk_size == 4

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Page
    ase._name = 'name'
    ase._encryption = None

    opts.chunk_size_bytes = upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES + 1
    with mock.patch(
            'blobxfer.models.upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES', 4):
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
        assert ud._chunk_size == 4

    with mock.patch('blobxfer.models.upload._MAX_PAGE_BLOB_SIZE', 4):
        with pytest.raises(RuntimeError):
            upload.Descriptor(
                lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())


def test_compute_total_chunks(tmpdir):
    tmpdir.join('a').ensure(file=True)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 0
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud.entity.size = upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
    with pytest.raises(RuntimeError):
        ud._compute_total_chunks(1)

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud.entity.size = upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
    ud._chunk_size = upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
    with pytest.raises(RuntimeError):
        ud._compute_total_chunks(1)

    ase._mode = azmodels.StorageModes.Append
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud.entity.size = upload._MAX_BLOCK_BLOB_CHUNKSIZE_BYTES
    ud._chunk_size = upload._MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES
    with pytest.raises(RuntimeError):
        ud._compute_total_chunks(1)


def test_resume(tmpdir):
    tmpdir.join('a').write('zz')
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 0
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    # test no resume
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), None)
    assert ud._resume() is None

    # check if path exists in resume db
    resume = mock.MagicMock()
    resume.get_record.return_value = None
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() is None

    # check same lengths
    bad = mock.MagicMock()
    bad.length = 0
    resume.get_record.return_value = bad
    assert ud._resume() is None

    # check completed resume
    comp = mock.MagicMock()
    comp.length = 2
    comp.completed = True
    comp.total_chunks = 1
    comp.chunk_size = 2
    comp.completed_chunks = 1
    resume.get_record.return_value = comp
    ud._completed_chunks = mock.MagicMock()
    ud._src_ase = ase
    assert ud._resume() == 2

    ase.replica_targets = [ase]
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    ud._completed_chunks = mock.MagicMock()
    ud._src_ase = ase
    assert ud._resume() == 4

    # check no encryption
    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    opts.rsa_public_key = 'abc'

    nc = mock.MagicMock()
    nc.length = 16
    nc.completed = False
    nc.total_chunks = 2
    nc.chunk_size = 1
    nc.completed_chunks = 1

    resume.get_record.return_value = nc
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() is None

    # check rr path exists
    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'

    nc.length = 2
    nc.local_path = pathlib.Path('yyy')
    opts.rsa_public_key = None

    resume.get_record.return_value = nc
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() is None

    # check resume no md5
    opts.store_file_properties.md5 = False

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'

    nc = mock.MagicMock()
    nc.length = 2
    nc.completed = False
    nc.total_chunks = 2
    nc.chunk_size = 1
    cc = bitstring.BitArray(length=nc.total_chunks)
    cc.set(True, 0)
    nc.completed_chunks = cc.int
    nc.local_path = lp.absolute_path

    resume.get_record.return_value = nc
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() == 1

    # check resume with md5 mismatch
    opts.store_file_properties.md5 = True

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'

    nc = mock.MagicMock()
    nc.length = 2
    nc.completed = False
    nc.total_chunks = 2
    nc.chunk_size = 1
    cc = bitstring.BitArray(length=nc.total_chunks)
    cc.set(True, 0)
    nc.completed_chunks = cc.int
    nc.local_path = lp.absolute_path

    resume.get_record.return_value = nc
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() is None

    # check resume with md5 match
    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'

    nc = mock.MagicMock()
    nc.length = 2
    nc.completed = False
    nc.total_chunks = 2
    nc.chunk_size = 1
    cc = bitstring.BitArray(length=nc.total_chunks)
    cc.set(True, 0)
    nc.completed_chunks = cc.int
    nc.local_path = lp.absolute_path
    md5 = hashlib.md5()
    md5.update(b'z')
    nc.md5hexdigest = md5.hexdigest()

    resume.get_record.return_value = nc
    ud = upload.Descriptor(lp, ase, 'uid', opts, mock.MagicMock(), resume)
    assert ud._resume() == 1


def test_descriptor_next_offsets(tmpdir):
    tmpdir.join('a').write('ab')
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    # test normal
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._resume = mock.MagicMock()
    ud._resume.return_value = None

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 1
    assert offsets.range_start == 0
    assert offsets.range_end == 0
    assert not offsets.pad
    assert ud._offset == 1
    assert ud._chunk_num == 1

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 1
    assert offsets.num_bytes == 1
    assert offsets.range_start == 1
    assert offsets.range_end == 1
    assert not offsets.pad
    assert ud._offset == 2
    assert ud._chunk_num == 2

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets is None

    # test chunk size exceeds size
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))
    opts.chunk_size_bytes = 3

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._chunk_size = 3
    ud._resume = mock.MagicMock()
    ud._resume.return_value = None

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 2
    assert offsets.range_start == 0
    assert offsets.range_end == 1
    assert not offsets.pad
    assert ud._offset == 2
    assert ud._chunk_num == 1

    # test encrypted
    tmpdir.join('a').write('z' * 16)
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))
    opts.chunk_size_bytes = 16
    opts.rsa_public_key = 'abc'

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._resume = mock.MagicMock()
    ud._resume.return_value = None

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 0
    assert offsets.num_bytes == 16
    assert offsets.range_start == 0
    assert offsets.range_end == 15
    assert not offsets.pad
    assert ud._offset == 16
    assert ud._chunk_num == 1

    offsets, rb = ud.next_offsets()
    assert rb is None
    assert offsets.chunk_num == 1
    assert offsets.num_bytes == 16
    assert offsets.range_start == 16
    assert offsets.range_end == 31
    assert offsets.pad
    assert ud._offset == 32
    assert ud._chunk_num == 2


def test_descriptor_read_data(tmpdir):
    tmpdir.join('a').write('ab')
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    # test normal
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._resume = mock.MagicMock()
    ud._resume.return_value = None

    # test no data to read
    mockoffsets = mock.MagicMock()
    mockoffsets.num_bytes = 0
    data, newoffset = ud.read_data(mockoffsets)
    assert data is None
    assert newoffset is None

    # test normal data to read
    offsets, rb = ud.next_offsets()
    assert rb is None
    data, newoffset = ud.read_data(offsets)
    assert data == b'a'
    assert newoffset is None

    # test stdin
    with mock.patch(
            'blobxfer.STDIN', new_callable=mock.PropertyMock) as patched_stdin:
        patched_stdin.read = mock.MagicMock()
        patched_stdin.read.return_value = b'z'
        ud.local_path.use_stdin = True
        data, newoffset = ud.read_data(offsets)
        assert data == b'z'
        assert newoffset.chunk_num == 0
        assert newoffset.num_bytes == 1
        assert newoffset.range_start == 0
        assert newoffset.range_end == 0
        assert not newoffset.pad
        assert ud._total_chunks == 3
        assert ud._outstanding_ops == 3
        assert ud._offset == 1
        assert ud.entity.size == 2

    with mock.patch(
            'blobxfer.STDIN', new_callable=mock.PropertyMock) as patched_stdin:
        patched_stdin.read = mock.MagicMock()
        patched_stdin.read.return_value = None
        ud.local_path.use_stdin = True
        data, newoffset = ud.read_data(offsets)
        assert data is None
        assert newoffset is None
        assert ud._total_chunks == 2
        assert ud._outstanding_ops == 2
        assert ud._chunk_num == 0


def test_descriptor_generate_metadata(tmpdir):
    tmpdir.join('a').write('ab')
    lp = upload.LocalPath(pathlib.Path(str(tmpdir)), pathlib.Path('a'))

    # test nothing
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.attributes = False
    opts.store_file_properties.md5 = False
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    meta = ud.generate_metadata()
    assert meta is None

    # test page md5 align
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.attributes = False
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Page
    ase._name = 'name'
    ase._encryption = None
    ase._size = 1

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud._offset = 1
    ud.md5 = hashlib.md5()
    ud.md5.update(b'z')
    meta = ud.generate_metadata()
    assert meta is None
    md5 = hashlib.md5()
    md5.update(b'z' + b'\0' * 511)
    assert ud.md5.digest() == md5.digest()

    # test fileattr meta
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.attributes = True
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    # file attr store is not avail on windows
    if not util.on_windows():
        ud = upload.Descriptor(
            lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
        meta = ud.generate_metadata()
        assert metadata.JSON_KEY_BLOBXFER_METADATA in meta
        assert metadata._JSON_KEY_FILE_ATTRIBUTES in meta[
            metadata.JSON_KEY_BLOBXFER_METADATA]

    # test enc meta
    opts.store_file_properties.attributes = False
    opts.store_file_properties.md5 = False
    opts.rsa_public_key = 'abc'
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ase.encryption_metadata = mock.MagicMock()
    ase.encryption_metadata.convert_to_json_with_mac.return_value = {
        'encmeta': 'encmeta'
    }
    meta = ud.generate_metadata()
    assert 'encmeta' in meta

    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ud.hmac = None
    ase.encryption_metadata = mock.MagicMock()
    ase.encryption_metadata.convert_to_json_with_mac.return_value = {
        'encmeta': 'encmeta'
    }
    meta = ud.generate_metadata()
    assert 'encmeta' in meta

    opts.store_file_properties.md5 = True
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    ase.encryption_metadata = mock.MagicMock()
    ase.encryption_metadata.convert_to_json_with_mac.return_value = {
        'encmeta': 'encmeta'
    }
    meta = ud.generate_metadata()
    assert 'encmeta' in meta

    # test vio meta
    opts = mock.MagicMock()
    opts.chunk_size_bytes = 1
    opts.one_shot_bytes = 0
    opts.store_file_properties.md5 = True
    opts.rsa_public_key = None

    ase = azmodels.StorageEntity('cont')
    ase._mode = azmodels.StorageModes.Block
    ase._name = 'name'
    ase._encryption = None

    lp.view = mock.MagicMock()
    lp.view.mode = upload.VectoredIoDistributionMode.Stripe
    ud = upload.Descriptor(
        lp, ase, 'uid', opts, mock.MagicMock(), mock.MagicMock())
    with mock.patch(
            'blobxfer.models.metadata.generate_vectored_io_stripe_metadata',
            return_value={'viometa': 'viometa'}):
        meta = ud.generate_metadata()
        assert metadata.JSON_KEY_BLOBXFER_METADATA in meta
        assert 'viometa' in meta[metadata.JSON_KEY_BLOBXFER_METADATA]
