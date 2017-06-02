# coding=utf-8
"""Tests for miscellaneous"""

# stdlib imports
# non-stdlib imports
import azure.storage
# module under test
import blobxfer.version


def test_user_agent_monkey_patch():
    verstr = 'blobxfer/{}'.format(blobxfer.version.__version__)
    assert azure.storage._constants.USER_AGENT_STRING.startswith(verstr)
