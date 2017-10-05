# coding=utf-8
"""Tests for miscellaneous"""

# stdlib imports
# non-stdlib imports
import azure.storage.common
# module under test
import blobxfer.version


def test_user_agent_monkey_patch():
    verstr = 'blobxfer/{}'.format(blobxfer.version.__version__)
    assert azure.storage.common._constants.USER_AGENT_STRING_PREFIX.startswith(
        verstr)
