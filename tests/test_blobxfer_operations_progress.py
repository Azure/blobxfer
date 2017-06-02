# coding=utf-8
"""Tests for progress operations"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
# local imports
import blobxfer.util as util
# module under test
import blobxfer.operations.progress as ops


def test_output_parameters():
    go = mock.MagicMock()
    spec = mock.MagicMock()
    go.log_file = 'abc'

    ops.output_parameters(go, spec)

    assert util.is_not_empty(go.log_file)


def test_update_progress_bar():
    go = mock.MagicMock()
    go.progress_bar = True
    go.log_file = 'abc'

    start = util.datetime_now()

    ops.update_progress_bar(
        go, 'download', start, None, 1, None, 1)

    with mock.patch('blobxfer.util.datetime_now') as patched_dt:
        patched_dt.return_value = start
        ops.update_progress_bar(
            go, 'synccopy', start, 1, 1, 1, 1)

    assert util.is_not_empty(go.log_file)
