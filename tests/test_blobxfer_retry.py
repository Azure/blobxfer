# coding=utf-8
"""Tests for retry"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import pytest
# module under test
import blobxfer.retry as retry


def test_exponentialretrywithmaxwait():
    with pytest.raises(ValueError):
        er = retry.ExponentialRetryWithMaxWait(
            initial_backoff=1, max_backoff=0)

    er = retry.ExponentialRetryWithMaxWait()
    context = mock.MagicMock()
    context.count = 0
    context.response.status = 500
    bo = er.retry(context)
    assert context.count == 1
    assert bo == 1

    bo = er.retry(context)
    assert context.count == 2
    assert bo == 2

    bo = er.retry(context)
    assert context.count == 3
    assert bo == 4

    bo = er.retry(context)
    assert context.count == 4
    assert bo == 8

    bo = er.retry(context)
    assert context.count == 1
    assert bo == 1
