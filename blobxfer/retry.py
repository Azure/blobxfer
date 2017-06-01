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
# non-stdlib imports
import azure.storage.retry
# local imports


class ExponentialRetryWithMaxWait(azure.storage.retry._Retry):
    """Exponential Retry with Max Wait (infinite retries)"""
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

    def retry(self, context):
        # type: (ExponentialRetryWithMaxWait,
        #        azure.storage.models.RetryContext) -> int
        """Retry handler
        :param ExponentialRetryWithMaxWait self: this
        :param azure.storage.models.RetryContext context: retry context
        :rtype: int or None
        :return: int
        """
        return self._retry(context, self._backoff)

    def _backoff(self, context):
        # type: (ExponentialRetryWithMaxWait,
        #        azure.storage.models.RetryContext) -> int
        """Backoff calculator
        :param ExponentialRetryWithMaxWait self: this
        :param azure.storage.models.RetryContext context: retry context
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
