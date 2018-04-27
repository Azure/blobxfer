# coding=utf-8
"""Tests for retry"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
# non-stdlib imports
import azure.storage.common.models
import pytest
import requests
import urllib3
# module under test
import blobxfer.retry as retry


def test_should_retry():
    er = retry.ExponentialRetryWithMaxWait()
    context = mock.MagicMock()
    context.count = 1
    er.max_attempts = 1
    assert not er._should_retry(context)

    context.count = 0
    er.max_attempts = 20
    context.response.status = None
    context.exception = requests.Timeout()
    assert er._should_retry(context)

    # test malformed
    ex = requests.ConnectionError(
        urllib3.exceptions.MaxRetryError(
            mock.MagicMock(), mock.MagicMock())
    )
    context.exception = ex
    assert not er._should_retry(context)

    ex = requests.ConnectionError(
        urllib3.exceptions.MaxRetryError(
            mock.MagicMock(), mock.MagicMock(),
            reason=urllib3.exceptions.NewConnectionError(
                list(retry._RETRYABLE_ERRNO_MAXRETRY)[0], 'message')
        )
    )
    context.exception = ex
    assert er._should_retry(context)

    ex = requests.ConnectionError(
        urllib3.exceptions.MaxRetryError(
            mock.MagicMock(), mock.MagicMock(),
            reason=urllib3.exceptions.NewConnectionError(
                '[Errno N]', 'message')
        )
    )
    context.exception = ex
    assert not er._should_retry(context)

    # test malformed
    ex = requests.ConnectionError(
        urllib3.exceptions.ProtocolError()
    )
    context.exception = ex
    assert not er._should_retry(context)

    ex = requests.ConnectionError(
        urllib3.exceptions.ProtocolError(
            '({}, message)'.format(list(retry._RETRYABLE_ERRNO_PROTOCOL)[0])
        )
    )
    context.exception = ex
    assert er._should_retry(context)

    ex = requests.ConnectionError(
        urllib3.exceptions.ProtocolError('(N, message)')
    )
    context.exception = ex
    assert not er._should_retry(context)

    ex = requests.exceptions.ContentDecodingError()
    context.exception = ex
    assert er._should_retry(context)

    context.exception = None
    context.response.status = 200
    assert er._should_retry(context)

    context.response.status = 300
    assert not er._should_retry(context)

    context.response.status = 404
    context.location_mode = azure.storage.common.models.LocationMode.SECONDARY
    assert er._should_retry(context)

    context.response.status = 408
    assert er._should_retry(context)

    context.response.status = 500
    assert er._should_retry(context)

    context.response.status = 501
    assert not er._should_retry(context)


def test_exponentialretrywithmaxwait():
    with pytest.raises(ValueError):
        er = retry.ExponentialRetryWithMaxWait(
            initial_backoff=1, max_backoff=0)

    with pytest.raises(ValueError):
        er = retry.ExponentialRetryWithMaxWait(
            initial_backoff=1, max_backoff=1, max_retries=-1)

    with pytest.raises(ValueError):
        er = retry.ExponentialRetryWithMaxWait(
            initial_backoff=2, max_backoff=1)

    er = retry.ExponentialRetryWithMaxWait()
    context = mock.MagicMock()
    context.count = 0
    context.response.status = 500
    bo = er.retry(context)
    assert context.count == 1
    assert bo == 0.1

    bo = er.retry(context)
    assert context.count == 2
    assert bo == 0.2

    bo = er.retry(context)
    assert context.count == 3
    assert bo == 0.4

    bo = er.retry(context)
    assert context.count == 4
    assert bo == 0.8

    bo = er.retry(context)
    assert context.count == 5
    assert bo == 0.1
