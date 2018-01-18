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
import threading
# non-stdlib imports
import bitstring
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
        #        blobxfer.models.azure.StorageEntity, list,
        #        blobxfer.models.options.SyncCopy,
        #        blobxfer.operations.resume.SyncCopyResumeManager) -> None
        """Ctor for Descriptor
        :param Descriptor self: this
        :param blobxfer.models.azure.StorageEntity src_ase:
            source Azure Storage Entity
        :param blobxfer.models.azure.StorageEntity dst_ase:
            destination Azure Storage Entity
        :param list block_list: source blob block list
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
        if self._resume_mgr:
            self._completed_chunks = bitstring.BitArray(
                length=self._total_chunks)
            self._replica_counters = {}

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
        return self.dst_entity.mode == blobxfer.models.azure.StorageModes.File

    @property
    def remote_is_page_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Page Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Page Blob
        """
        return self.dst_entity.mode == blobxfer.models.azure.StorageModes.Page

    @property
    def remote_is_append_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Append Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Append Blob
        """
        return (
            self.dst_entity.mode == blobxfer.models.azure.StorageModes.Append
        )

    @property
    def remote_is_block_blob(self):
        # type: (Descriptor) -> bool
        """Remote destination is an Azure Block Blob
        :param Descriptor self: this
        :rtype: bool
        :return: remote is an Azure Block Blob
        """
        return self.dst_entity.mode == blobxfer.models.azure.StorageModes.Block

    @property
    def is_one_shot_block_blob(self):
        # type: (Descriptor) -> bool
        """Is one shot block blob
        :param Descriptor self: this
        :rtype: bool
        :return: if upload is a one-shot block blob
        """
        return self.remote_is_block_blob and self._total_chunks == 1

    @property
    def requires_put_block_list(self):
        # type: (Descriptor) -> bool
        """Requires a put block list operation to finalize
        :param Descriptor self: this
        :rtype: bool
        :return: if finalize requires a put block list
        """
        return self.remote_is_block_blob and self._total_chunks > 1

    @property
    def requires_access_tier_set(self):
        # type: (Descriptor) -> bool
        """Remote destination requires an access tier set operation
        :param Descriptor self: this
        :rtype: bool
        :return: access tier is set
        """
        return (self.remote_is_block_blob and
                self.dst_entity.access_tier is not None)

    def complete_offset_upload(self, chunk_num):
        # type: (Descriptor, int) -> None
        """Complete the upload for the offset
        :param Descriptor self: this
        :param int chunk_num: chunk num completed
        """
        with self._meta_lock:
            self._outstanding_ops -= 1
            # save resume state
            if self.is_resumable:
                # only set resumable completed if all replicas for this
                # chunk are complete
                if blobxfer.util.is_not_empty(self._dst_ase.replica_targets):
                    if chunk_num not in self._replica_counters:
                        # start counter at -1 since we need 1 "extra" for the
                        # primary in addition to the replica targets
                        self._replica_counters[chunk_num] = -1
                    self._replica_counters[chunk_num] += 1
                    if (self._replica_counters[chunk_num] !=
                            len(self._dst_ase.replica_targets)):
                        return
                    else:
                        self._replica_counters.pop(chunk_num)
                self._completed_chunks.set(True, chunk_num)
                completed = self._outstanding_ops == 0
                self._resume_mgr.add_or_update_record(
                    self._dst_ase, self._src_block_list, self._offset,
                    self._chunk_size, self._total_chunks,
                    self._completed_chunks.int, completed,
                )

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
        if self._resume_mgr is None or self._offset > 0:
            return None
        # check if path exists in resume db
        rr = self._resume_mgr.get_record(self._dst_ase)
        if rr is None:
            logger.debug('no resume record for {}'.format(self._dst_ase.path))
            return None
        # ensure lengths are the same
        if rr.length != self._src_ase.size:
            logger.warning('resume length mismatch {} -> {}'.format(
                rr.length, self._src_ase.size))
            return None
        # compute replica factor
        if blobxfer.util.is_not_empty(self._dst_ase.replica_targets):
            replica_factor = 1 + len(self._dst_ase.replica_targets)
        else:
            replica_factor = 1
        # set offsets if completed
        if rr.completed:
            with self._meta_lock:
                logger.debug('{} upload already completed'.format(
                    self._dst_ase.path))
                self._offset = rr.offset
                self._src_block_list = rr.src_block_list
                self._chunk_num = rr.total_chunks
                self._chunk_size = rr.chunk_size
                self._total_chunks = rr.total_chunks
                self._completed_chunks.int = rr.completed_chunks
                self._outstanding_ops = 0
                return self._src_ase.size * replica_factor
        # re-hash from 0 to offset if needed
        _cc = bitstring.BitArray(length=rr.total_chunks)
        _cc.int = rr.completed_chunks
        curr_chunk = _cc.find('0b0')[0]
        del _cc
        # set values from resume
        with self._meta_lock:
            self._offset = rr.offset
            self._src_block_list = rr.src_block_list
            self._chunk_num = curr_chunk
            self._chunk_size = rr.chunk_size
            self._total_chunks = rr.total_chunks
            self._completed_chunks = bitstring.BitArray(length=rr.total_chunks)
            self._completed_chunks.set(True, range(0, curr_chunk + 1))
            self._outstanding_ops = (
                (rr.total_chunks - curr_chunk) * replica_factor
            )
            logger.debug(
                ('resuming file {} from byte={} chunk={} chunk_size={} '
                 'total_chunks={} outstanding_ops={}').format(
                     self._src_ase.path, self._offset, self._chunk_num,
                     self._chunk_size, self._total_chunks,
                     self._outstanding_ops))
            return rr.offset * replica_factor

    def next_offsets(self):
        # type: (Descriptor) -> Offsets
        """Retrieve the next offsets
        :param Descriptor self: this
        :rtype: Offsets
        :return: download offsets
        """
        resume_bytes = self._resume()
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
