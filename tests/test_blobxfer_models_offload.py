# coding=utf-8
"""Tests for offload"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import pytest
# local imports
# module under test
import blobxfer.models.offload as offload


def test_multiprocess_offload():
    with pytest.raises(ValueError):
        a = offload._MultiprocessOffload(None, None)

    target = mock.MagicMock()
    a = offload._MultiprocessOffload(target, 1, 'test')
    assert len(a._procs) == 1
    assert not a.terminated
    assert a._done_cv == a.done_cv
    assert a._check_thread is None
    assert a.pop_done_queue() is None

    item = (0, 'abc')
    a._done_queue.put(item)

    check_func = mock.MagicMock()
    a.initialize_check_thread(check_func)

    a.finalize_processes()
    assert a.terminated
    for proc in a._procs:
        assert not proc.is_alive()

    assert a.pop_done_queue() == item
