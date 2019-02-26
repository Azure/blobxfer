# coding=utf-8
"""Tests for progress operations"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
# local imports
import blobxfer.models.azure as azmodels
import blobxfer.models.download as modelsdl
import blobxfer.models.options as options
import blobxfer.models.synccopy as modelssc
import blobxfer.models.upload as modelsul
import blobxfer.util as util
# module under test
import blobxfer.operations.progress as ops


def test_output_parameters():
    go = mock.MagicMock()
    go.quiet = False
    go.log_file = 'abc'

    spec = modelsdl.Specification(
        download_options=options.Download(
            check_file_md5=True,
            chunk_size_bytes=4194304,
            delete_extraneous_destination=False,
            max_single_object_concurrency=8,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=False,
            restore_file_properties=options.FileProperties(
                attributes=False,
                cache_control=None,
                lmt=False,
                md5=None,
            ),
            rsa_private_key=None,
            strip_components=0,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        ),
        local_destination_path=mock.MagicMock(),
    )
    ops.output_parameters(go, spec)
    assert util.is_not_empty(go.log_file)

    spec = modelsul.Specification(
        upload_options=options.Upload(
            access_tier='cool',
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
                cache_control='cc',
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
        local_source_path=mock.MagicMock()
    )
    ops.output_parameters(go, spec)
    assert util.is_not_empty(go.log_file)

    spec = modelssc.Specification(
        synccopy_options=options.SyncCopy(
            access_tier='archive',
            delete_extraneous_destination=False,
            dest_mode=azmodels.StorageModes.Auto,
            mode=azmodels.StorageModes.Auto,
            overwrite=True,
            recursive=True,
            rename=False,
        ),
        skip_on_options=options.SkipOn(
            filesize_match=True,
            lmt_ge=False,
            md5_match=True,
        )
    )
    ops.output_parameters(go, spec)
    assert util.is_not_empty(go.log_file)


def test_update_progress_bar():
    go = mock.MagicMock()
    go.quiet = False
    go.progress_bar = True
    go.log_file = 'abc'

    start = util.datetime_now()

    ops.update_progress_bar(
        go, 'download', start, None, 1, None, 1)

    ops.update_progress_bar(
        go, 'upload', start, 1, 0, 256, 0, stdin_upload=True)

    with mock.patch('blobxfer.util.datetime_now') as patched_dt:
        patched_dt.return_value = start
        ops.update_progress_bar(
            go, 'synccopy', start, 1, 1, 1, 1)

    assert util.is_not_empty(go.log_file)
