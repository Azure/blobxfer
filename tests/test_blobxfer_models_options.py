# coding=utf-8
"""Tests for models options"""

# stdlib imports
try:
    import unittest.mock as mock
except ImportError:  # noqa
    import mock
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
# non-stdlib imports
import pytest
# module under test
import blobxfer.models.options as options


@mock.patch('multiprocessing.cpu_count', return_value=1)
def test_concurrency_options(patched_cc):
    a = options.Concurrency(
        crypto_processes=-1,
        md5_processes=0,
        disk_threads=-1,
        transfer_threads=-2,
    )

    assert a.crypto_processes == 0
    assert a.md5_processes == 1
    assert a.disk_threads == 2
    assert a.transfer_threads == 4

    a = options.Concurrency(
        crypto_processes=-1,
        md5_processes=0,
        disk_threads=1,
        transfer_threads=-1,
    )

    assert a.crypto_processes == 0
    assert a.md5_processes == 1
    assert a.disk_threads == 1
    assert a.transfer_threads == 4


@mock.patch('multiprocessing.cpu_count', return_value=64)
def test_concurrency_options_max_disk_and_transfer_threads(patched_cc):
    a = options.Concurrency(
        crypto_processes=1,
        md5_processes=1,
        disk_threads=None,
        transfer_threads=None,
    )

    assert a.disk_threads == 64
    assert a.transfer_threads == 96


def test_general_options():
    a = options.General(
        concurrency=options.Concurrency(
            crypto_processes=1,
            md5_processes=2,
            disk_threads=3,
            transfer_threads=4,
        ),
        log_file='abc.log',
        progress_bar=False,
        resume_file='abc',
        timeout_sec=1,
        verbose=True,
    )

    assert a.concurrency.crypto_processes == 1
    assert a.concurrency.md5_processes == 2
    assert a.concurrency.disk_threads == 3
    assert a.concurrency.transfer_threads == 4
    assert a.log_file == 'abc.log'
    assert not a.progress_bar
    assert a.resume_file == pathlib.Path('abc')
    assert a.timeout_sec == 1
    assert a.verbose

    a = options.General(
        concurrency=options.Concurrency(
            crypto_processes=1,
            md5_processes=2,
            disk_threads=3,
            transfer_threads=4,
        ),
        progress_bar=False,
        resume_file=None,
        timeout_sec=1,
        verbose=True,
    )

    assert a.concurrency.crypto_processes == 1
    assert a.concurrency.md5_processes == 2
    assert a.concurrency.disk_threads == 3
    assert a.concurrency.transfer_threads == 4
    assert a.log_file is None
    assert not a.progress_bar
    assert a.resume_file is None
    assert a.timeout_sec == 1
    assert a.verbose

    with pytest.raises(ValueError):
        a = options.General(None)
