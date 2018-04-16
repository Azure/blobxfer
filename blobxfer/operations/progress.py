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
import logging
import os
import platform
import sys
# non-stdlib imports
import azure.storage.blob
import azure.storage.file
import cryptography
import requests
# local imports
import blobxfer.models.download
import blobxfer.models.synccopy
import blobxfer.models.upload
import blobxfer.util
import blobxfer.version

# create logger
logger = logging.getLogger(__name__)


def update_progress_bar(
        go, optext, start, total_files, files_sofar, total_bytes,
        bytes_sofar, stdin_upload=False):
    # type: (blobxfer.models.options.General, str, datetime.datetime, int,
    #        int, int, int, bool) -> None
    """Update the progress bar
    :param blobxfer.models.options.General go: general options
    :param str optext: operation prefix text
    :param datetime.datetime start: start time
    :param int total_files: total number of files
    :param int files_sofar: files transfered so far
    :param int total_bytes: total number of bytes
    :param int bytes_sofar: bytes transferred so far
    :param bool stdin_upload: stdin upload
    """
    if (go.quiet or not go.progress_bar or
            blobxfer.util.is_none_or_empty(go.log_file) or
            start is None):
        return
    diff = (blobxfer.util.datetime_now() - start).total_seconds()
    if diff <= 0:
        # arbitrarily give a small delta
        diff = 1e-9
    if total_bytes is None or total_bytes == 0 or bytes_sofar > total_bytes:
        done = 0
    else:
        done = float(bytes_sofar) / total_bytes
    rate = bytes_sofar / blobxfer.util.MEGABYTE / diff
    if optext == 'synccopy':
        rtext = 'sync-copied'
    else:
        rtext = optext + 'ed'
    if total_files is None:
        fprog = 'n/a'
    else:
        fprog = '{}/{}'.format(files_sofar, total_files)
    if stdin_upload:
        sys.stdout.write(
            ('\r{0} progress: [{1:30s}]   n/a % {2:12.3f} MiB/sec, '
             '{3} {4}').format(
                 optext, '>' * int(total_bytes % 30), rate, fprog, rtext)
        )
    else:
        sys.stdout.write(
            ('\r{0} progress: [{1:30s}] {2:.2f}% {3:12.3f} MiB/sec, '
             '{4} {5}').format(
                 optext, '>' * int(done * 30), done * 100, rate, fprog, rtext)
        )
    if files_sofar == total_files:
        sys.stdout.write(os.linesep)
    sys.stdout.flush()


def output_parameters(general_options, spec):
    # type: (blobxfer.models.options.General, object) -> None
    """Output parameters
    :param blobxfer.models.options.General general_options: general options
    :param object spec: upload or download spec
    """
    if general_options.quiet:
        return
    sep = '============================================'
    log = []
    log.append(sep)
    log.append('         Azure blobxfer parameters')
    log.append(sep)
    log.append('         blobxfer version: {}'.format(
        blobxfer.version.__version__))
    log.append('                 platform: {}'.format(platform.platform()))
    log.append(
        ('               components: {}={}-{} azstor.blob={} azstor.file={} '
         'crypt={} req={}').format(
            platform.python_implementation(),
            platform.python_version(),
             '64bit' if sys.maxsize > 2**32 else '32bit',
            azure.storage.blob._constants.__version__,
            azure.storage.file._constants.__version__,
            cryptography.__version__,
            requests.__version__,))
    # specific preamble
    if isinstance(spec, blobxfer.models.download.Specification):
        log.append('       transfer direction: {}'.format('Azure -> local'))
        log.append(
            ('                  workers: disk={} xfer={} md5={} '
             'crypto={}').format(
                 general_options.concurrency.disk_threads,
                 general_options.concurrency.transfer_threads,
                 general_options.concurrency.md5_processes
                 if spec.options.check_file_md5 else 0,
                 general_options.concurrency.crypto_processes))
    elif isinstance(spec, blobxfer.models.upload.Specification):
        log.append('       transfer direction: {}'.format('local -> Azure'))
        log.append(
            ('                  workers: disk={} xfer={} md5={} '
             'crypto={}').format(
                 general_options.concurrency.disk_threads,
                 general_options.concurrency.transfer_threads,
                 general_options.concurrency.md5_processes
                 if spec.skip_on.md5_match or
                 spec.options.store_file_properties.md5 else 0,
                 0))
    elif isinstance(spec, blobxfer.models.synccopy.Specification):
        log.append('       transfer direction: {}'.format('Azure -> Azure'))
        log.append(
            ('                  workers: disk={} xfer={} md5={} '
             'crypto={}').format(
                 general_options.concurrency.disk_threads,
                 general_options.concurrency.transfer_threads,
                 general_options.concurrency.md5_processes,
                 general_options.concurrency.crypto_processes))
    # common block
    log.append('                 log file: {}'.format(
        general_options.log_file))
    log.append('              resume file: {}'.format(
        general_options.resume_file))
    log.append('                  timeout: connect={} read={}'.format(
        general_options.timeout.connect, general_options.timeout.read))
    if isinstance(spec, blobxfer.models.synccopy.Specification):
        log.append('              source mode: {}'.format(
            spec.options.mode))
        log.append('                dest mode: {}'.format(
            spec.options.dest_mode))
    else:
        log.append('                     mode: {}'.format(
            spec.options.mode))
    log.append(
        '                  skip on: fs_match={} lmt_ge={} md5={}'.format(
            spec.skip_on.filesize_match,
            spec.skip_on.lmt_ge,
            spec.skip_on.md5_match))
    log.append('        delete extraneous: {}'.format(
        spec.options.delete_extraneous_destination))
    log.append('                overwrite: {}'.format(
        spec.options.overwrite))
    log.append('                recursive: {}'.format(
        spec.options.recursive))
    log.append('            rename single: {}'.format(
        spec.options.rename))
    # specific epilog
    if isinstance(spec, blobxfer.models.download.Specification):
        log.append('         chunk size bytes: {}'.format(
            spec.options.chunk_size_bytes))
        log.append('         strip components: {}'.format(
            spec.options.strip_components))
        log.append('         compute file md5: {}'.format(
            spec.options.check_file_md5))
        log.append('  restore file attributes: {}'.format(
            spec.options.restore_file_attributes))
        log.append('          rsa private key: {}'.format(
            'Loaded' if spec.options.rsa_private_key else 'None'))
        log.append('        local destination: {}'.format(
            spec.destination.path))
    elif isinstance(spec, blobxfer.models.upload.Specification):
        log.append('              access tier: {}'.format(
            spec.options.access_tier))
        log.append('         chunk size bytes: {}'.format(
            spec.options.chunk_size_bytes))
        log.append('           one shot bytes: {}'.format(
            spec.options.one_shot_bytes))
        log.append('         strip components: {}'.format(
            spec.options.strip_components))
        log.append('         store properties: attr={} md5={}'.format(
            spec.options.store_file_properties.attributes,
            spec.options.store_file_properties.md5))
        log.append('           rsa public key: {}'.format(
            'Loaded' if spec.options.rsa_public_key else 'None'))
        log.append('       local source paths: {}'.format(
            ' '.join([str(src) for src in spec.sources.paths])))
    elif isinstance(spec, blobxfer.models.synccopy.Specification):
        log.append('              access tier: {}'.format(
            spec.options.access_tier))
    log.append(sep)
    log = os.linesep.join(log)
    if blobxfer.util.is_not_empty(general_options.log_file):
        print(log)
    logger.info('{}{}'.format(os.linesep, log))
