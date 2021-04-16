# coding=utf-8
"""Tests for models options"""

# stdlib imports
import unittest.mock as mock
import pathlib
# non-stdlib imports
import pytest
# module under test
import blobxfer.models.options as options


def test_timeout():
    a = options.Timeout(connect=None, read=1, max_retries=-1)
    assert a.connect == options._DEFAULT_REQUESTS_TIMEOUT[0]
    assert a.read == 1
    assert a.timeout == (options._DEFAULT_REQUESTS_TIMEOUT[0], 1)
    assert a.max_retries is None

    a = options.Timeout(connect=2, read=0, max_retries=3)
    assert a.connect == 2
    assert a.read == options._DEFAULT_REQUESTS_TIMEOUT[1]
    assert a.timeout == (2, options._DEFAULT_REQUESTS_TIMEOUT[1])
    assert a.max_retries == 3


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

    a = options.Concurrency(
        crypto_processes=1,
        md5_processes=1,
        disk_threads=None,
        transfer_threads=None,
        action=1,
    )

    assert a.disk_threads == 45
    assert a.transfer_threads == 30

    a = options.Concurrency(
        crypto_processes=1,
        md5_processes=1,
        disk_threads=None,
        transfer_threads=None,
        action=3,
    )

    assert a.md5_processes == 0
    assert a.crypto_processes == 0
    assert a.disk_threads == 0
    assert a.transfer_threads == 96


@mock.patch('multiprocessing.cpu_count', return_value=6)
def test_concurrency_options_max_disk_and_transfer_threads2(patched_cc):
    a = options.Concurrency(
        crypto_processes=1,
        md5_processes=1,
        disk_threads=None,
        transfer_threads=None,
        action=1,
    )

    assert a.disk_threads == 4
    assert a.transfer_threads == 3


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
        timeout=options.Timeout(1, 2, None),
        quiet=True,
        dry_run=True,
        verbose=True,
    )

    assert a.concurrency.crypto_processes == 1
    assert a.concurrency.md5_processes == 2
    assert a.concurrency.disk_threads == 3
    assert a.concurrency.transfer_threads == 4
    assert a.log_file == 'abc.log'
    assert not a.progress_bar
    assert a.resume_file == pathlib.Path('abc')
    assert a.timeout.timeout == (1, 2)
    assert a.timeout.max_retries is None
    assert a.quiet
    assert a.dry_run
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
        timeout=options.Timeout(2, 1, 0),
        verbose=True,
    )

    assert a.concurrency.crypto_processes == 1
    assert a.concurrency.md5_processes == 2
    assert a.concurrency.disk_threads == 3
    assert a.concurrency.transfer_threads == 4
    assert a.log_file is None
    assert not a.progress_bar
    assert a.resume_file is None
    assert a.timeout.timeout == (2, 1)
    assert a.timeout.max_retries == 0
    assert not a.quiet
    assert not a.dry_run
    assert a.verbose

    with pytest.raises(ValueError):
        a = options.General(None)
