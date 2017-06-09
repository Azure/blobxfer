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
import collections
import logging
import math
import os
import threading
# non-stdlib imports
# local imports
import blobxfer.models.azure
import blobxfer.models.crypto
import blobxfer.models.options
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)
# global defines
_MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES = 4194304
# named tuples
Offsets = collections.namedtuple(
    'Offsets', [
        'chunk_num',
        'num_bytes',
        'range_end',
        'range_start',
    ]
)


class Specification(object):
    """Synccopy Specification"""
    def __init__(self, synccopy_options, skip_on_options):
        # type: (Specification, blobxfer.models.options.SyncCopy,
        #        blobxfer.models.options.SkipOn, LocalDestinationPath) -> None
        """Ctor for Specification
        :param DownloadSpecification self: this
        :param blobxfer.models.options.SyncCopy synccopy_options:
            synccopy options
        :param blobxfer.models.options.SkipOn skip_on_options: skip on options
        """
        self.options = synccopy_options
        self.skip_on = skip_on_options
        self.sources = []
        self.destinations = []

    def add_azure_source_path(self, source):
        # type: (Specification, blobxfer.operations.azure.SourcePath) -> None
        """Add an Azure Source Path
        :param DownloadSpecification self: this
        :param blobxfer.operations.Azure.SourcePath source:
            Azure source path to add
        """
        self.sources.append(source)

    def add_azure_destination_path(self, dest):
        # type: (Specification,
        #        blobxfer.operations.azure.DestinationPath) -> None
        """Add a remote Azure Destination path
        :param UploadSpecification self: this
        :param blobxfer.operations.azure.DestinationPath dest:
            Remote destination path
        """
        self.destinations.append(dest)


class Descriptor(object):
    """Synccopy Descriptor"""
    def __init__(self, src_ase, dst_ase, block_list, options, resume_mgr):
        # type: (Descriptior, blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.options.SyncCopy,
        #        blobxfer.operations.resume.SyncCopyResumeManager) -> None
        """Ctor for Descriptor
        :param Descriptor self: this
        :param blobxfer.models.azure.StorageEntity ase: Azure Storage Entity
        :param blobxfer.models.options.SyncCopy options: synccopy options
        :param blobxfer.operations.resume.SyncCopyResumeManager resume_mgr:
            synccopy resume manager
        """
        self._offset = 0
        self._chunk_num = 0
        self._finalized = False
        self._meta_lock = threading.Lock()
        self._resume_mgr = resume_mgr
        self._src_ase = src_ase
        self._dst_ase = dst_ase
        self._src_block_list = block_list
        self._chunk_size = self._compute_chunk_size()
        # calculate the total number of ops required for transfer
        self._total_chunks = self._compute_total_chunks(self._chunk_size)
        self._outstanding_ops = self._total_chunks
        if blobxfer.util.is_not_empty(self._dst_ase.replica_targets):
            self._outstanding_ops *= len(self._dst_ase.replica_targets) + 1

    @property
    def src_entity(self):
        # type: (Descriptor) -> blobxfer.models.azure.StorageEntity
        """Get linked source blobxfer.models.azure.StorageEntity
        :param Descriptor self: this
        :rtype: blobxfer.models.azure.StorageEntity
        :return: blobxfer.models.azure.StorageEntity
        """
        return self._src_ase

    @property
    def dst_entity(self):
        # type: (Descriptor) -> blobxfer.models.azure.StorageEntity
        """Get linked destination blobxfer.models.azure.StorageEntity
        :param Descriptor self: this
        :rtype: blobxfer.models.azure.StorageEntity
        :return: blobxfer.models.azure.StorageEntity
        """
        return self._dst_ase

    @property
    def all_operations_completed(self):
        # type: (Descriptor) -> bool
        """All operations are completed
        :param Descriptor self: this
        :rtype: bool
        :return: if all operations completed
        """
        with self._meta_lock:
            return self._outstanding_ops == 0

    @property
    def is_resumable(self):
        # type: (Descriptor) -> bool
        """Download is resume capable
        :param Descriptor self: this
        :rtype: bool
        :return: if resumable
        """
        return self._resume_mgr is not None

    @property
    def last_block_num(self):
        # type: (Descriptor) -> bool
        """Last used block number for block id, should only be called for
        finalize operation
        :param Descriptor self: this
        :rtype: int
        :return: block number
        """
        with self._meta_lock:
            return self._chunk_num - 1

    @property
    def remote_is_file(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure File
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure File
        """
        return self.src_entity.mode == blobxfer.models.azure.StorageModes.File

    @property
    def remote_is_page_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Page Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Page Blob
        """
        return self.src_entity.mode == blobxfer.models.azure.StorageModes.Page

    @property
    def remote_is_append_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Append Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Append Blob
        """
        return (
            self.src_entity.mode == blobxfer.models.azure.StorageModes.Append
        )

    @property
    def is_one_shot_block_blob(self):
        # type: (Descriptor) -> bool
        """Is one shot block blob
        :param Descriptor self: this
        :rtype: bool
        :return: if upload is a one-shot block blob
        """
        return (
            self.src_entity.mode ==
            blobxfer.models.azure.StorageModes.Block and
            self._total_chunks == 1
        )

    @property
    def requires_put_block_list(self):
        # type: (Descriptor) -> bool
        """Requires a put block list operation to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put block list
        """
        return (
            self.src_entity.mode ==
            blobxfer.models.azure.StorageModes.Block and
            self._total_chunks > 1
        )

    def complete_offset_upload(self, chunk_num):
        # type: (Descriptor, int) -> None
        """Complete the upload for the offset
        :param Descriptor self: this
        :param int chunk_num: chunk num completed
        """
        with self._meta_lock:
            self._outstanding_ops -= 1

            # save resume state
            # TODO fix issue with replica targets
#             if self.is_resumable:
#                 self._completed_chunks.set(True, chunk_num)
#                 completed = self._outstanding_ops == 0
#                 if not completed and self.must_compute_md5:
#                     last_consecutive = (
#                         self._completed_chunks.find('0b0')[0] - 1
#                     )
#                     md5digest = self._md5_cache[last_consecutive]
#                 else:
#                     md5digest = None
#                     if completed:
#                         last_consecutive = None
#                         self._md5_cache.clear()
#                 self._resume_mgr.add_or_update_record(
#                     self.local_path.absolute_path, self._ase, self._chunk_size,
#                     self._total_chunks, self._completed_chunks.int, completed,
#                     md5digest,
#                 )
#                 # prune md5 cache
#                 if len(self._md5_cache) > _MAX_MD5_CACHE_RESUME_ENTRIES:
#                     mkeys = sorted(list(self._md5_cache.keys()))
#                     for key in mkeys:
#                         if key >= last_consecutive:
#                             break
#                         self._md5_cache.pop(key)

    def _compute_chunk_size(self):
        # type: (Descriptor) -> int
        """Compute chunk size given block list
        :param Descriptor self: this
        :rtype: int
        :return: chunk size bytes
        """
        if self._src_block_list is not None:
            blen = len(self._src_block_list)
            if blen == 0:
                # this is a one-shot block blob
                return self._src_ase.size
            elif blen == 1:
                return self._src_block_list[0].size
            else:
                return -1
        else:
            return _MAX_NONBLOCK_BLOB_CHUNKSIZE_BYTES

    def _compute_total_chunks(self, chunk_size):
        # type: (Descriptor, int) -> int
        """Compute total number of chunks for entity
        :param Descriptor self: this
        :param int chunk_size: chunk size
        :rtype: int
        :return: num chunks
        """
        try:
            if self._src_block_list is not None:
                blen = len(self._src_block_list)
                if blen > 0:
                    return blen
                else:
                    return 1
            else:
                return int(math.ceil(self._src_ase.size / chunk_size))
        except ZeroDivisionError:
            return 1

    def _resume(self):
        # type: (Descriptor) -> int
        """Resume a download, if possible
        :param Descriptor self: this
        :rtype: int or None
        :return: verified download offset
        """
        if self._resume_mgr is None or self._offset > 0 or self._finalized:
            return None
        # check if path exists in resume db
        rr = self._resume_mgr.get_record(self._ase)
        if rr is None:
            logger.debug('no resume record for {}'.format(self.final_path))
            return None
        # ensure lengths are the same
        if rr.length != self._ase.size:
            logger.warning('resume length mismatch {} -> {}'.format(
                rr.length, self._ase.size))
            return None
        # calculate current chunk and offset
        if rr.next_integrity_chunk == 0:
            logger.debug('nothing to resume for {}'.format(self.final_path))
            return None
        curr_chunk = rr.next_integrity_chunk
        # set offsets if completed and the final path exists
        if rr.completed and self.final_path.exists():
            with self._meta_lock:
                logger.debug('{} download already completed'.format(
                    self.final_path))
                self._offset = self._ase.size
                self._chunk_num = curr_chunk
                self._chunk_size = rr.chunk_size
                self._total_chunks = self._compute_total_chunks(rr.chunk_size)
                self._next_integrity_chunk = rr.next_integrity_chunk
                self._outstanding_ops = 0
                self._finalized = True
            return self._ase.size
        # encrypted files are not resumable due to hmac requirement
        if self._ase.is_encrypted:
            logger.debug('cannot resume encrypted entity {}'.format(
                self._ase.path))
            return None
        self._allocate_disk_space()
        # check if final path exists
        if not self.final_path.exists():
            logger.warning('download path {} does not exist'.format(
                self.final_path))
            return None
        if self.hmac is not None:
            raise RuntimeError(
                'unexpected hmac object for entity {}'.format(self._ase.path))
        # re-hash from 0 to offset if needed
        _fd_offset = 0
        _end_offset = min((curr_chunk * rr.chunk_size, rr.length))
        if self.md5 is not None and curr_chunk > 0:
            _blocksize = blobxfer.util.MEGABYTE << 2
            logger.debug(
                'integrity checking existing file {} offset {} -> {}'.format(
                    self.final_path,
                    self.view.fd_start,
                    self.view.fd_start + _end_offset)
            )
            with self._hasher_lock:
                with self.final_path.open('rb') as filedesc:
                    filedesc.seek(self.view.fd_start, 0)
                    while _fd_offset < _end_offset:
                        if (_fd_offset + _blocksize) > _end_offset:
                            _blocksize = _end_offset - _fd_offset
                        _buf = filedesc.read(_blocksize)
                        self.md5.update(_buf)
                        _fd_offset += _blocksize
            del _blocksize
            # compare hashes
            hexdigest = self.md5.hexdigest()
            if rr.md5hexdigest != hexdigest:
                logger.warning(
                    'MD5 mismatch resume={} computed={} for {}'.format(
                         rr.md5hexdigest, hexdigest, self.final_path))
                # reset hasher
                self.md5 = blobxfer.util.new_md5_hasher()
                return None
        # set values from resume
        with self._meta_lock:
            self._offset = _end_offset
            self._chunk_num = curr_chunk
            self._chunk_size = rr.chunk_size
            self._total_chunks = self._compute_total_chunks(rr.chunk_size)
            self._next_integrity_chunk = rr.next_integrity_chunk
            self._outstanding_ops = (
                self._total_chunks - self._next_integrity_chunk
            )
            logger.debug(
                ('resuming file {} from byte={} chunk={} chunk_size={} '
                 'total_chunks={} next_integrity_chunk={} '
                 'outstanding_ops={}').format(
                     self.final_path, self._offset, self._chunk_num,
                     self._chunk_size, self._total_chunks,
                     self._next_integrity_chunk, self._outstanding_ops))
        return _end_offset

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: download offsets
        """
        # TODO resume
        #resume_bytes = self._resume()
        resume_bytes = None
        with self._meta_lock:
            if self._chunk_num >= self._total_chunks:
                return None, resume_bytes
            if self._chunk_size == -1 and self._src_block_list is not None:
                num_bytes = self._src_block_list[self._chunk_num].size
            else:
                if self._offset + self._chunk_size > self._src_ase.size:
                    num_bytes = self._src_ase.size - self._offset
                else:
                    num_bytes = self._chunk_size
            chunk_num = self._chunk_num
            range_start = self._offset
            range_end = self._offset + num_bytes - 1
            self._offset += num_bytes
            self._chunk_num += 1
            return Offsets(
                chunk_num=chunk_num,
                num_bytes=num_bytes,
                range_start=range_start,
                range_end=range_end,
            ), resume_bytes

    def _update_resume_for_completed(self):
        # type: (Descriptor) -> None
        """Update resume for completion
        :param Descriptor self: this
        """
        if not self.is_resumable:
            return
        with self._meta_lock:
            self._resume_mgr.add_or_update_record(
                self.final_path, self._ase, self._chunk_size,
                self._next_integrity_chunk, True, None,
            )

    def finalize_integrity(self):
        # type: (Descriptor) -> None
        """Finalize integrity check for download
        :param Descriptor self: this
        """
        with self._meta_lock:
            if self._finalized:
                return
        # check final file integrity
        check = False
        msg = None
        if self.hmac is not None:
            mac = self._ase.encryption_metadata.encryption_authentication.\
                message_authentication_code
            digest = blobxfer.util.base64_encode_as_string(self.hmac.digest())
            if digest == mac:
                check = True
            msg = '{}: {}, {} {} <L..R> {}'.format(
                self._ase.encryption_metadata.encryption_authentication.
                algorithm,
                'OK' if check else 'MISMATCH',
                self._ase.path,
                digest,
                mac,
            )
        elif self.md5 is not None:
            digest = blobxfer.util.base64_encode_as_string(self.md5.digest())
            if digest == self._ase.md5:
                check = True
            msg = 'MD5: {}, {} {} <L..R> {}'.format(
                'OK' if check else 'MISMATCH',
                self._ase.path,
                digest,
                self._ase.md5,
            )
        else:
            check = True
            msg = 'MD5: SKIPPED, {} None <L..R> {}'.format(
                self._ase.path,
                self._ase.md5
            )
        # cleanup if download failed
        if not check:
            self._integrity_failed = True
            logger.error(msg)
        logger.info(msg)

    def _restore_file_attributes(self):
        # type: (Descriptor) -> None
        """Restore file attributes for file
        :param Descriptor self: this
        """
        if self._ase.file_attributes is None:
            return
        # set file uid/gid and mode
        if blobxfer.util.on_windows():
            # TODO not implemented yet
            pass
        else:
            self.final_path.chmod(int(self._ase.file_attributes.mode, 8))
            if os.getuid() == 0:
                os.chown(
                    str(self.final_path),
                    self._ase.file_attributes.uid,
                    self._ase.file_attributes.gid
                )

    def finalize_file(self):
        # type: (Descriptor) -> None
        """Finalize file for download
        :param Descriptor self: this
        """
        # delete bad file if integrity failed
        if self._integrity_failed:
            self.final_path.unlink()
        else:
            self._restore_file_attributes()
        # update resume file
        self._update_resume_for_completed()
        with self._meta_lock:
            self._finalized = True
