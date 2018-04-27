# Copyright (c) Microsoft Corporation
#
# All rights reserved.
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

# compat imports
from __future__ import (
    absolute_import, division, print_function, unicode_literals
)
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip)
# stdlib imports
import errno
# non-stdlib imports
import azure.storage.common.models
import azure.storage.common.retry
import requests
import urllib3
# local imports


# global defines
_RETRYABLE_ERRNO_MAXRETRY = frozenset((
    '[Errno {}]'.format(errno.ECONNRESET),
    '[Errno {}]'.format(errno.ECONNREFUSED),
    '[Errno {}]'.format(errno.ECONNABORTED),
    '[Errno {}]'.format(errno.ENETRESET),
    '[Errno {}]'.format(errno.ETIMEDOUT),
))
_RETRYABLE_ERRNO_PROTOCOL = frozenset((
    '({},'.format(errno.ECONNRESET),
    '({},'.format(errno.ECONNREFUSED),
    '({},'.format(errno.ECONNABORTED),
    '({},'.format(errno.ENETRESET),
    '({},'.format(errno.ETIMEDOUT),
))


class ExponentialRetryWithMaxWait(azure.storage.common.retry._Retry):
    """Exponential Retry with Max Wait Reset"""
    def __init__(
            self, initial_backoff=0.1, max_backoff=1, max_retries=None,
            reset_at_max=True):
        # type: (ExponentialRetryWithMaxWait, int, int, int, bool) -> None
        """Ctor for ExponentialRetryWithMaxWait
        :param ExponentialRetryWithMaxWait self: this
        :param int initial_backoff: initial backoff
        :param int max_backoff: max backoff
        :param int max_retries: max retries
        :param bool reset_at_max: reset after reaching max wait
        """
        if max_backoff <= 0:
            raise ValueError(
                'max backoff is non-positive: {}'.format(max_backoff))
        if max_retries is not None and max_retries < 0:
            raise ValueError(
                'max retries is invalid: {}'.format(max_retries))
        if max_backoff < initial_backoff:
            raise ValueError(
                'max backoff {} less than initial backoff {}'.format(
                    max_backoff, initial_backoff))
        self._backoff_count = 0
        self._last_backoff = initial_backoff
        self.initial_backoff = initial_backoff
        self.max_backoff = max_backoff
        self.reset_at_max = reset_at_max
        super(ExponentialRetryWithMaxWait, self).__init__(
            max_retries if max_retries is not None else 2147483647, False)

    def _should_retry(self, context):
        # type: (ExponentialRetryWithMaxWait,
        #        azure.storage.common.models.RetryContext) -> bool
        """Determine if retry should happen or not
        :param ExponentialRetryWithMaxWait self: this
        :param azure.storage.common.models.RetryContext context: retry context
        :rtype: bool
        :return: True if retry should happen, False otherwise
        """
        # do not retry if max attempts equal or exceeded
        if context.count >= self.max_attempts:
            return False

        # get response status
        status = None
        if context.response and context.response.status:
            status = context.response.status

        # if there is no response status, then handle the exception
        # appropriately from the lower layer
        if status is None:
            exc = context.exception
            # default to not retry in unknown/unhandled exception case
            ret = False
            # requests timeout, retry
            if isinstance(exc, requests.Timeout):
                ret = True
            elif isinstance(exc, requests.exceptions.ContentDecodingError):
                ret = True
            elif (isinstance(exc, requests.exceptions.ConnectionError) or
                  isinstance(exc, requests.exceptions.ChunkedEncodingError)):
                # newer versions of requests do not expose errno on the
                # args[0] reason object; manually string parse
                if isinstance(exc.args[0], urllib3.exceptions.MaxRetryError):
                    try:
                        msg = exc.args[0].reason.args[0]
                    except (AttributeError, IndexError):
                        # unexpected/malformed exception hierarchy, don't retry
                        pass
                    else:
                        if any(x in msg for x in _RETRYABLE_ERRNO_MAXRETRY):
                            ret = True
                elif isinstance(exc.args[0], urllib3.exceptions.ProtocolError):
                    try:
                        msg = exc.args[0].args[0]
                    except (AttributeError, IndexError):
                        # unexpected/malformed exception hierarchy, don't retry
                        pass
                    else:
                        if any(x in msg for x in _RETRYABLE_ERRNO_PROTOCOL):
                            ret = True
            return ret
        elif 200 <= status < 300:
            # failure during respond body download or parsing, so success
            # codes should be retried
            return True
        elif 300 <= status < 500:
            # response code 404 should be retried if secondary was used
            if (status == 404 and
                    context.location_mode ==
                    azure.storage.common.models.LocationMode.SECONDARY):
                return True
            # response code 408 is a timeout and should be retried
            if status == 408:
                return True
            return False
        elif status >= 500:
            # response codes above 500 should be retried except for
            # 501 (not implemented) and 505 (version not supported)
            if status == 501 or status == 505:
                return False
            return True
        else:  # noqa
            # this should be unreachable, retry anyway
            return True

    def retry(self, context):
        # type: (ExponentialRetryWithMaxWait,
        #        azure.storage.common.models.RetryContext) -> int
        """Retry handler
        :param ExponentialRetryWithMaxWait self: this
        :param azure.storage.common.models.RetryContext context: retry context
        :rtype: int or None
        :return: int
        """
        return self._retry(context, self._backoff)

    def _backoff(self, context):
        # type: (ExponentialRetryWithMaxWait,
        #        azure.storage.common.models.RetryContext) -> int
        """Backoff calculator
        :param ExponentialRetryWithMaxWait self: this
        :param azure.storage.common.models.RetryContext context: retry context
        :rtype: int
        :return: backoff amount
        """
        self._backoff_count += 1
        if self._backoff_count == 1:
            self._last_backoff = self.initial_backoff
        else:
            self._last_backoff *= 2
        if self._last_backoff > self.max_backoff and self.reset_at_max:
            self._backoff_count = 1
            self._last_backoff = self.initial_backoff
        return self._last_backoff
