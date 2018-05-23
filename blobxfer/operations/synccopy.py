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
import enum
import logging
try:
    import pathlib2 as pathlib
except ImportError:  # noqa
    import pathlib
try:
    import queue
except ImportError:  # noqa
    import Queue as queue
import threading
# non-stdlib imports
# local imports
import blobxfer.models.metadata
import blobxfer.operations.azure.blob
import blobxfer.operations.azure.file
import blobxfer.operations.md5
import blobxfer.operations.progress
import blobxfer.operations.resume
import blobxfer.util

# create logger
logger = logging.getLogger(__name__)


class SynccopyAction(enum.Enum):
    Skip = 1
    Copy = 2


class SyncCopy(object):
    """SyncCopy"""
    def __init__(self, general_options, creds, spec):
        # type: (SyncCopy, blobxfer.models.options.General,
        #        blobxfer.operations.azure.StorageCredentials,
        #        blobxfer.models.synccopy.Specification) -> None
        """Ctor for SyncCopy
        :param SyncCopy self: this
        :param blobxfer.models.options.General general_options: general opts
        :param blobxfer.operations.azure.StorageCredentials creds: creds
        :param blobxfer.models.synccopy.Specification spec: download spec
        """
        self._all_remote_files_processed = False
        self._transfer_lock = threading.Lock()
        self._transfer_threads = []
        self._transfer_queue = queue.Queue()
        self._transfer_set = set()
        self._synccopy_start_time = None
        self._synccopy_total = 0
        self._synccopy_sofar = 0
        self._synccopy_bytes_total = 0
        self._synccopy_bytes_sofar = 0
        self._synccopy_terminate = False
        self._start_time = None
        self._delete_exclude = set()
        self._containers_created = set()
        self._fileshare_dir_lock = threading.Lock()
        self._dirs_created = {}
        self._general_options = general_options
        self._creds = creds
        self._spec = spec
        self._resume = None
        self._exceptions = []

    @property
    def termination_check(self):
        # type: (SyncCopy) -> bool
        """Check if terminated
        :param SyncCopy self: this
        :rtype: bool
        :return: if terminated
        """
        with self._transfer_lock:
            return (self._synccopy_terminate or
                    len(self._exceptions) > 0 or
                    (self._all_remote_files_processed and
                     len(self._transfer_set) == 0))

    @staticmethod
    def create_unique_transfer_operation_id(src_ase, dst_ase):
        # type: (blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.azure.StorageEntity) -> str
        """Create a unique transfer operation id
        :param blobxfer.models.azure.StorageEntity src_ase: src storage entity
        :param blobxfer.models.azure.StorageEntity dst_ase: dst storage entity
        :rtype: str
        :return: unique transfer id
        """
        return ';'.join(
            (src_ase._client.primary_endpoint, src_ase.path,
             dst_ase._client.primary_endpoint, dst_ase.path)
        )

    @staticmethod
    def create_deletion_id(client, container, name):
        # type: (azure.storage.StorageClient, str, str) -> str
        """Create a unique deletion id
        :param azure.storage.StorageClient client: storage client
        :param str container: container name
        :param str name: entity name
        :rtype: str
        :return: unique id for deletion
        """
        return ';'.join((client.primary_endpoint, container, name))

    def _update_progress_bar(self):
        # type: (SyncCopy) -> None
        """Update progress bar
        :param SyncCopy self: this
        """
        blobxfer.operations.progress.update_progress_bar(
            self._general_options,
            'synccopy',
            self._synccopy_start_time,
            self._synccopy_total,
            self._synccopy_sofar,
            self._synccopy_bytes_total,
            self._synccopy_bytes_sofar,
        )

    def _global_dest_mode_is_file(self):
        # type: (SyncCopy) -> bool
        """Determine if destination mode is file
        :param SyncCopy self: this
        :rtype: bool
        :return: destination mode is file
        """
        if (self._spec.options.dest_mode ==
                blobxfer.models.azure.StorageModes.File or
                (self._spec.options.mode ==
                 blobxfer.models.azure.StorageModes.File and
                 self._spec.options.dest_mode ==
                 blobxfer.models.azure.StorageModes.Auto)):
            return True
        return False

    def _translate_src_mode_to_dst_mode(self, src_mode):
        # type: (SyncCopy, blobxfer.models.azure.StorageModes) -> bool
        """Translate the source mode into the destination mode
        :param SyncCopy self: this
        :param blobxfer.models.azure.StorageModes src_mode: source mode
        :rtype: blobxfer.models.azure.StorageModes
        :return: destination mode
        """
        if (self._spec.options.dest_mode ==
                blobxfer.models.azure.StorageModes.Auto):
            return src_mode
        else:
            return self._spec.options.dest_mode

    def _delete_extraneous_files(self):
        # type: (SyncCopy) -> None
        """Delete extraneous files on the remote
        :param SyncCopy self: this
        """
        if not self._spec.options.delete_extraneous_destination:
            return
        # list blobs for all destinations
        checked = set()
        deleted = 0
        for sa, container, _, _ in self._get_destination_paths():
            key = ';'.join((sa.name, sa.endpoint, container))
            if key in checked:
                continue
            logger.debug(
                'attempting to delete extraneous blobs/files from: {}'.format(
                    key))
            if self._global_dest_mode_is_file():
                files = blobxfer.operations.azure.file.list_all_files(
                    sa.file_client, container)
                for file in files:
                    id = blobxfer.operations.synccopy.SyncCopy.\
                        create_deletion_id(sa.file_client, container, file)
                    if id not in self._delete_exclude:
                        if self._general_options.verbose:
                            logger.debug('deleting file: {}'.format(file))
                        blobxfer.operations.azure.file.delete_file(
                            sa.file_client, container, file)
                        deleted += 1
            else:
                blobs = blobxfer.operations.azure.blob.list_all_blobs(
                    sa.block_blob_client, container)
                for blob in blobs:
                    id = blobxfer.operations.synccopy.SyncCopy.\
                        create_deletion_id(
                            sa.block_blob_client, container, blob.name)
                    if id not in self._delete_exclude:
                        if self._general_options.verbose:
                            logger.debug('deleting blob: {}'.format(blob.name))
                        blobxfer.operations.azure.blob.delete_blob(
                            sa.block_blob_client, container, blob.name)
                        deleted += 1
            checked.add(key)
        logger.info('deleted {} extraneous blobs/files'.format(deleted))

    def _add_to_transfer_queue(self, src_ase, dst_ase):
        # type: (SyncCopy, blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.azure.StorageEntity) -> None
        """Add remote file to download queue
        :param SyncCopy self: this
        :param blobxfer.models.azure.StorageEntity src_ase: src ase
        :param blobxfer.models.azure.StorageEntity dst_ase: dst ase
        """
        # prepare remote file for download
        # if remote file is a block blob, need to retrieve block list
        if (src_ase.mode == dst_ase.mode ==
                blobxfer.models.azure.StorageModes.Block):
            bl = blobxfer.operations.azure.blob.block.get_committed_block_list(
                src_ase)
        else:
            bl = None
        # TODO future optimization for page blob synccopies: query
        # page ranges and omit cleared pages from being transferred
        sd = blobxfer.models.synccopy.Descriptor(
            src_ase, dst_ase, bl, self._spec.options, self._resume)
        # add download descriptor to queue
        self._transfer_queue.put(sd)
        if self._synccopy_start_time is None:
            with self._transfer_lock:
                if self._synccopy_start_time is None:
                    self._synccopy_start_time = blobxfer.util.datetime_now()

    def _initialize_transfer_threads(self):
        # type: (SyncCopy) -> None
        """Initialize transfer threads
        :param SyncCopy self: this
        """
        logger.debug('spawning {} transfer threads'.format(
            self._general_options.concurrency.transfer_threads))
        for _ in range(self._general_options.concurrency.transfer_threads):
            thr = threading.Thread(target=self._worker_thread_transfer)
            self._transfer_threads.append(thr)
            thr.start()

    def _wait_for_transfer_threads(self, terminate):
        # type: (SyncCopy, bool) -> None
        """Wait for download threads
        :param SyncCopy self: this
        :param bool terminate: terminate threads
        """
        if terminate:
            self._synccopy_terminate = terminate
        for thr in self._transfer_threads:
            blobxfer.util.join_thread(thr)

    def _worker_thread_transfer(self):
        # type: (SyncCopy) -> None
        """Worker thread download
        :param SyncCopy self: this
        """
        while not self.termination_check:
            try:
                sd = self._transfer_queue.get(block=False, timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._process_synccopy_descriptor(sd)
            except Exception as e:
                with self._transfer_lock:
                    self._exceptions.append(e)

    def _put_data(self, sd, ase, offsets, data):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor,
        #        blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.upload.Offsets, bytes) -> None
        """Put data in Azure
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param blobxfer.models.azure.StorageEntity ase: Storage entity
        :param blobxfer.models.upload.Offsets offsets: offsets
        :param bytes data: data to upload
        """
        if ase.mode == blobxfer.models.azure.StorageModes.Append:
            # append block
            if data is not None:
                blobxfer.operations.azure.blob.append.append_block(ase, data)
        elif ase.mode == blobxfer.models.azure.StorageModes.Block:
            # handle one-shot uploads
            if sd.is_one_shot_block_blob:
                if blobxfer.util.is_not_empty(sd.src_entity.md5):
                    digest = sd.src_entity.md5
                else:
                    digest = None
                blobxfer.operations.azure.blob.block.create_blob(
                    ase, data, digest, sd.src_entity.raw_metadata)
                return
            # upload block
            if data is not None:
                blobxfer.operations.azure.blob.block.put_block(
                    ase, offsets, data)
        elif ase.mode == blobxfer.models.azure.StorageModes.File:
            # upload range
            if data is not None:
                blobxfer.operations.azure.file.put_file_range(
                    ase, offsets, data)
        elif ase.mode == blobxfer.models.azure.StorageModes.Page:
            if data is not None:
                # compute aligned size
                aligned = blobxfer.util.page_align_content_length(
                    offsets.num_bytes)
                # align page
                if aligned != offsets.num_bytes:
                    data = data.ljust(aligned, b'\0')
                if blobxfer.operations.md5.check_data_is_empty(data):
                    return
                # upload page
                blobxfer.operations.azure.blob.page.put_page(
                    ase, offsets.range_start,
                    offsets.range_start + aligned - 1, data)

    def _process_data(self, sd, ase, offsets, data):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor,
        #        blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.synccopy.Offsets, bytes) -> None
        """Process downloaded data for upload
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param blobxfer.models.azure.StorageEntity ase: storage entity
        :param blobxfer.models.synccopy.Offsets offsets: offsets
        :param bytes data: data to process
        """
        # issue put data
        self._put_data(sd, ase, offsets, data)
        # accounting
        with self._transfer_lock:
            self._synccopy_bytes_sofar += offsets.num_bytes
        # complete offset upload and save resume state
        sd.complete_offset_upload(offsets.chunk_num)

    def _prepare_upload(self, ase):
        # type: (SyncCopy, blobxfer.models.azure.StorageEntity) -> None
        """Prepare upload
        :param SyncCopy self: this
        :param blobxfer.models.azure.StorageEntity ase: Storage entity
        """
        if ase.mode == blobxfer.models.azure.StorageModes.Append:
            if ase.append_create:
                # create container if necessary
                blobxfer.operations.azure.blob.create_container(
                    ase, self._containers_created)
                # create remote blob
                blobxfer.operations.azure.blob.append.create_blob(ase)
        elif ase.mode == blobxfer.models.azure.StorageModes.Block:
            # create container if necessary
            blobxfer.operations.azure.blob.create_container(
                ase, self._containers_created)
        elif ase.mode == blobxfer.models.azure.StorageModes.File:
            # create share directory structure
            with self._fileshare_dir_lock:
                # create container if necessary
                blobxfer.operations.azure.file.create_share(
                    ase, self._containers_created)
                # create parent directories
                blobxfer.operations.azure.file.create_all_parent_directories(
                    ase, self._dirs_created)
            # create remote file
            blobxfer.operations.azure.file.create_file(ase)
        elif ase.mode == blobxfer.models.azure.StorageModes.Page:
            # create container if necessary
            blobxfer.operations.azure.blob.create_container(
                ase, self._containers_created)
            # create remote blob
            blobxfer.operations.azure.blob.page.create_blob(ase)

    def _process_synccopy_descriptor(self, sd):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor) -> None
        """Process synccopy descriptor
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        """
        # update progress bar
        self._update_progress_bar()
        # get download offsets
        offsets, resume_bytes = sd.next_offsets()
        # add resume bytes to counter
        if resume_bytes is not None:
            with self._transfer_lock:
                self._synccopy_bytes_sofar += resume_bytes
                logger.debug('adding {} sofar {} from {}'.format(
                    resume_bytes, self._synccopy_bytes_sofar,
                    sd.dst_entity.name))
            del resume_bytes
        # check if all operations completed
        if offsets is None and sd.all_operations_completed:
            # finalize upload for non-one shots
            if not sd.is_one_shot_block_blob:
                self._finalize_upload(sd)
            else:
                # set access tier for one shots
                if sd.requires_access_tier_set:
                    blobxfer.operations.azure.blob.block.set_blob_access_tier(
                        sd.dst_entity)
            # accounting
            with self._transfer_lock:
                self._transfer_set.remove(
                    blobxfer.operations.synccopy.SyncCopy.
                    create_unique_transfer_operation_id(
                        sd.src_entity, sd.dst_entity))
                self._synccopy_sofar += 1
            return
        # re-enqueue for finalization if no offsets
        if offsets is None:
            self._transfer_queue.put(sd)
            return
        # prepare upload
        if offsets.chunk_num == 0:
            self._prepare_upload(sd.dst_entity)
        # prepare replica targets
        if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
            for ase in sd.dst_entity.replica_targets:
                if offsets.chunk_num == 0:
                    self._prepare_upload(ase)
        # re-enqueue for other threads to download next offset if not append
        if sd.src_entity.mode != blobxfer.models.azure.StorageModes.Append:
            self._transfer_queue.put(sd)
        # issue get range
        if sd.src_entity.mode == blobxfer.models.azure.StorageModes.File:
            data = blobxfer.operations.azure.file.get_file_range(
                sd.src_entity, offsets)
        else:
            data = blobxfer.operations.azure.blob.get_blob_range(
                sd.src_entity, offsets)
        # process data for upload
        self._process_data(sd, sd.dst_entity, offsets, data)
        # iterate replicas
        if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
            for ase in sd.dst_entity.replica_targets:
                self._process_data(sd, ase, offsets, data)
        # re-enqueue for append blobs
        if sd.src_entity.mode == blobxfer.models.azure.StorageModes.Append:
            self._transfer_queue.put(sd)

    def _finalize_block_blob(self, sd, metadata, digest):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor, dict,
        #        str) -> None
        """Finalize Block blob
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param dict metadata: metadata dict
        :param str digest: md5 digest
        """
        blobxfer.operations.azure.blob.block.put_block_list(
            sd.dst_entity, sd.last_block_num, digest, metadata)
        if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
            for ase in sd.dst_entity.replica_targets:
                blobxfer.operations.azure.blob.block.put_block_list(
                    ase, sd.last_block_num, digest, metadata)

    def _set_blob_md5(self, sd, digest):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor, str) -> None
        """Set blob MD5
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param str digest: md5 digest
        """
        blobxfer.operations.azure.blob.set_blob_md5(sd.dst_entity, digest)
        if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
            for ase in sd.dst_entity.replica_targets:
                blobxfer.operations.azure.blob.set_blob_md5(ase, digest)

    def _set_blob_metadata(self, sd, metadata):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor, dict) -> None
        """Set blob metadata
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param dict metadata: metadata dict
        :param dict metadata: metadata dict
        """
        blobxfer.operations.azure.blob.set_blob_metadata(
            sd.dst_entity, metadata)
        if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
            for ase in sd.dst_entity.replica_targets:
                blobxfer.operations.azure.blob.set_blob_metadata(ase, metadata)

    def _finalize_nonblock_blob(self, sd, metadata, digest):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor, dict,
        #        str) -> None
        """Finalize Non-Block blob
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param dict metadata: metadata dict
        :param str digest: md5 digest
        """
        # set md5 page blob property if required
        if blobxfer.util.is_not_empty(digest):
            self._set_blob_md5(sd, digest)
        # set metadata if needed
        if blobxfer.util.is_not_empty(metadata):
            self._set_blob_metadata(sd, metadata)

    def _finalize_azure_file(self, sd, metadata, digest):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor, dict,
        #        str) -> None
        """Finalize Azure File
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        :param dict metadata: metadata dict
        :param str digest: md5 digest
        """
        # set md5 file property if required
        if blobxfer.util.is_not_empty(digest):
            blobxfer.operations.azure.file.set_file_md5(sd.dst_entity, digest)
            if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
                for ase in sd.dst_entity.replica_targets:
                    blobxfer.operations.azure.file.set_file_md5(ase, digest)
        # set file metadata if needed
        if blobxfer.util.is_not_empty(metadata):
            blobxfer.operations.azure.file.set_file_metadata(
                sd.dst_entity, metadata)
            if blobxfer.util.is_not_empty(sd.dst_entity.replica_targets):
                for ase in sd.dst_entity.replica_targets:
                    blobxfer.operations.azure.file.set_file_metadata(
                        ase, metadata)

    def _finalize_upload(self, sd):
        # type: (SyncCopy, blobxfer.models.synccopy.Descriptor) -> None
        """Finalize file upload
        :param SyncCopy self: this
        :param blobxfer.models.synccopy.Descriptor sd: synccopy descriptor
        """
        metadata = sd.src_entity.raw_metadata
        if blobxfer.util.is_not_empty(sd.src_entity.md5):
            digest = sd.src_entity.md5
        else:
            digest = None
        if sd.requires_put_block_list:
            # put block list for non one-shot block blobs
            self._finalize_block_blob(sd, metadata, digest)
        elif sd.remote_is_page_blob or sd.remote_is_append_blob:
            # append and page blob finalization
            self._finalize_nonblock_blob(sd, metadata, digest)
        elif sd.remote_is_file:
            # azure file finalization
            self._finalize_azure_file(sd, metadata, digest)
        # set access tier
        if sd.requires_access_tier_set:
            blobxfer.operations.azure.blob.block.set_blob_access_tier(
                sd.dst_entity)

    def _check_copy_conditions(self, src, dst):
        # type: (SyncCopy, blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.azure.StorageEntity) -> UploadAction
        """Check for synccopy conditions
        :param SyncCopy self: this
        :param blobxfer.models.azure.StorageEntity src: src
        :param blobxfer.models.azure.StorageEntity dst: dst
        :rtype: SynccopyAction
        :return: synccopy action
        """
        # if remote file doesn't exist, copy
        if dst is None or dst.from_local:
            return SynccopyAction.Copy
        # check overwrite option
        if not self._spec.options.overwrite:
            logger.info(
                'not overwriting remote file: {})'.format(dst.path))
            return SynccopyAction.Skip
        # check skip on options, MD5 match takes priority
        src_md5 = blobxfer.models.metadata.get_md5_from_metadata(src)
        dst_md5 = blobxfer.models.metadata.get_md5_from_metadata(dst)
        if (self._spec.skip_on.md5_match and
                blobxfer.util.is_not_empty(src_md5)):
            if src_md5 == dst_md5:
                return SynccopyAction.Skip
            else:
                return SynccopyAction.Copy
        # if neither of the remaining skip on actions are activated, copy
        if (not self._spec.skip_on.filesize_match and
                not self._spec.skip_on.lmt_ge):
            return SynccopyAction.Copy
        # check skip on file size match
        ul_fs = None
        if self._spec.skip_on.filesize_match:
            if src.size == dst.size:
                ul_fs = False
            else:
                ul_fs = True
        # check skip on lmt ge
        ul_lmt = None
        if self._spec.skip_on.lmt_ge:
            if dst.lmt >= src.lmt:
                ul_lmt = False
            else:
                ul_lmt = True
        # upload if either skip on mismatch is True
        if ul_fs or ul_lmt:
            return SynccopyAction.Copy
        else:
            return SynccopyAction.Skip

    def _check_for_existing_remote(self, sa, cont, name, mode):
        # type: (SyncCopy, blobxfer.operations.azure.StorageAccount, str, str,
        #        blobxfer.models.azure.StorageModes) ->
        #        bobxfer.models.azure.StorageEntity
        """Check for an existing remote file
        :param SyncCopy self: this
        :param blobxfer.operations.azure.StorageAccount sa: storage account
        :param str cont: container
        :param str name: entity name
        :param blobxfer.models.StorageModes mode: dest mode
        :rtype: blobxfer.models.azure.StorageEntity
        :return: remote storage entity
        """
        if mode == blobxfer.models.azure.StorageModes.File:
            fp = blobxfer.operations.azure.file.get_file_properties(
                sa.file_client, cont, name)
        else:
            fp = blobxfer.operations.azure.blob.get_blob_properties(
                sa.block_blob_client, cont, name, mode)
        if fp is not None:
            if blobxfer.models.crypto.EncryptionMetadata.\
                    encryption_metadata_exists(fp.metadata):
                ed = blobxfer.models.crypto.EncryptionMetadata()
                ed.convert_from_json(fp.metadata, fp.name, None)
            else:
                ed = None
            ase = blobxfer.models.azure.StorageEntity(cont, ed)
            if mode == blobxfer.models.azure.StorageModes.File:
                dir, _, _ = blobxfer.operations.azure.file.parse_file_path(
                    name)
                ase.populate_from_file(sa, fp, dir)
            else:
                ase.populate_from_blob(sa, fp)
        else:
            ase = None
        return ase

    def _get_destination_paths(self):
        # type: (SyncCopy) ->
        #        Tuple[blobxfer.operations.azure.StorageAccount, str, str, str]
        """Get destination paths
        :param SyncCopy self: this
        :rtype: tuple
        :return: (storage account, container, name, dpath)
        """
        for dst in self._spec.destinations:
            for dpath in dst.paths:
                sdpath = str(dpath)
                cont, dir = blobxfer.util.explode_azure_path(sdpath)
                sa = self._creds.get_storage_account(
                    dst.lookup_storage_account(sdpath))
                yield sa, cont, dir, dpath

    def _generate_destination_for_source(self, src_ase):
        # type: (SyncCopy, blobxfer.models.azure.StorageEntity) ->
        #        blobxfer.models.azure.StorageEntity)
        """Generate entities for source path
        :param SyncCopy self: this
        :param blobxfer.models.azure.StorageEntity src_ase: source ase
        :rtype: blobxfer.models.azure.StorageEntity
        :return: destination storage entity
        """
        # create a storage entity for each destination
        for sa, cont, name, dpath in self._get_destination_paths():
            if self._spec.options.rename:
                name = str(pathlib.Path(name))
                if name == '.':
                    raise RuntimeError(
                        'attempting rename multiple files to a directory')
            else:
                name = str(pathlib.Path(name) / src_ase.name)
            # translate source mode to dest mode
            dst_mode = self._translate_src_mode_to_dst_mode(src_ase.mode)
            dst_ase = self._check_for_existing_remote(sa, cont, name, dst_mode)
            if dst_ase is None:
                dst_ase = blobxfer.models.azure.StorageEntity(cont, ed=None)
                dst_ase.populate_from_local(sa, cont, name, dst_mode)
                dst_ase.size = src_ase.size
            # overwrite tier with specified storage tier
            if (dst_mode == blobxfer.models.azure.StorageModes.Block and
                    self._spec.options.access_tier is not None):
                dst_ase.access_tier = self._spec.options.access_tier
            # check condition for dst
            action = self._check_copy_conditions(src_ase, dst_ase)
            if action == SynccopyAction.Copy:
                yield dst_ase
            elif action == SynccopyAction.Skip:
                # add to exclusion set if skipping
                if self._spec.options.delete_extraneous_destination:
                    uid = (
                        blobxfer.operations.synccopy.SyncCopy.
                        create_deletion_id(
                            dst_ase._client, dst_ase.container, dst_ase.name)
                    )
                    self._delete_exclude.add(uid)

    def _bind_sources_to_destination(self):
        # type: (SyncCopy) ->
        #        Tuple[blobxfer.models.azure.StorageEntity,
        #        blobxfer.models.azure.StorageEntity]
        """Bind source storage entity to destination storage entities
        :param SyncCopy self: this
        :rtype: tuple
        :return: (source storage entity, destination storage entity)
        """
        seen = set()
        # iterate through source paths to download
        for src in self._spec.sources:
            for src_ase in src.files(self._creds, self._spec.options):
                # generate copy destinations for source
                dest = [
                    dst_ase for dst_ase in
                    self._generate_destination_for_source(src_ase)
                ]
                if len(dest) == 0:
                    continue
                primary_dst = dest[0]
                uid = blobxfer.operations.synccopy.SyncCopy.create_deletion_id(
                    primary_dst._client, primary_dst.container,
                    primary_dst.name)
                if uid in seen:
                    raise RuntimeError(
                        'duplicate destination entity detected: {}/{}'.format(
                            primary_dst._client.primary_endpoint,
                            primary_dst.path))
                seen.add(uid)
                # add to exclusion set
                if self._spec.options.delete_extraneous_destination:
                    self._delete_exclude.add(uid)
                if len(dest[1:]) > 0:
                    if primary_dst.replica_targets is None:
                        primary_dst.replica_targets = []
                    primary_dst.replica_targets.extend(dest[1:])
                    # check replica targets for duplicates
                    for rt in primary_dst.replica_targets:
                        ruid = (
                            blobxfer.operations.synccopy.SyncCopy.
                            create_deletion_id(
                                rt._client, rt.container, rt.name)
                        )
                        if ruid in seen:
                            raise RuntimeError(
                                ('duplicate destination entity detected: '
                                 '{}/{}').format(
                                     rt._client.primary_endpoint, rt.path))
                        seen.add(ruid)
                        # add replica targets to deletion exclusion set
                        if self._spec.options.delete_extraneous_destination:
                            self._delete_exclude.add(ruid)
                yield src_ase, primary_dst

    def _run(self):
        # type: (SyncCopy) -> None
        """Execute SyncCopy
        :param SyncCopy self: this
        """
        # mark start
        self._start_time = blobxfer.util.datetime_now()
        logger.info('blobxfer start time: {0}'.format(self._start_time))
        # initialize resume db if specified
        if self._general_options.resume_file is not None:
            self._resume = blobxfer.operations.resume.SyncCopyResumeManager(
                self._general_options.resume_file)
        # initialize download threads
        self._initialize_transfer_threads()
        # iterate through source paths to download
        for src_ase, dst_ase in self._bind_sources_to_destination():
            # add transfer to set
            with self._transfer_lock:
                self._transfer_set.add(
                    blobxfer.operations.synccopy.SyncCopy.
                    create_unique_transfer_operation_id(src_ase, dst_ase))
                self._synccopy_total += 1
                self._synccopy_bytes_total += src_ase.size
                if blobxfer.util.is_not_empty(dst_ase.replica_targets):
                    self._synccopy_bytes_total += (
                        len(dst_ase.replica_targets) * src_ase.size
                    )
            self._add_to_transfer_queue(src_ase, dst_ase)
        # set remote files processed
        with self._transfer_lock:
            self._all_remote_files_processed = True
            synccopy_size_mib = (
                self._synccopy_bytes_total / blobxfer.util.MEGABYTE
            )
            logger.debug(
                ('{0} remote files processed, waiting for copy '
                 'completion of approx. {1:.4f} MiB').format(
                     self._synccopy_total, synccopy_size_mib))
        # wait for downloads to complete
        self._wait_for_transfer_threads(terminate=False)
        end_time = blobxfer.util.datetime_now()
        # update progress bar
        self._update_progress_bar()
        # check for exceptions
        if len(self._exceptions) > 0:
            logger.error('exceptions encountered while downloading')
            # raise the first one
            raise self._exceptions[0]
        # check for mismatches
        if (self._synccopy_sofar != self._synccopy_total or
                self._synccopy_bytes_sofar != self._synccopy_bytes_total):
            raise RuntimeError(
                'copy mismatch: [count={}/{} bytes={}/{}]'.format(
                    self._synccopy_sofar, self._synccopy_total,
                    self._synccopy_bytes_sofar, self._synccopy_bytes_total))
        # delete all remaining local files not accounted for if
        # delete extraneous enabled
        self._delete_extraneous_files()
        # delete resume file if we've gotten this far
        if self._resume is not None:
            self._resume.delete()
        # output throughput
        if self._synccopy_start_time is not None:
            dltime = (end_time - self._synccopy_start_time).total_seconds()
            synccopy_size_mib = (
                (self._synccopy_bytes_total << 1) / blobxfer.util.MEGABYTE
            )
            dlmibspeed = synccopy_size_mib / dltime
            logger.info(
                ('elapsed copy time and throughput of {0:.4f} '
                 'GiB: {1:.3f} sec, {2:.4f} Mbps ({3:.3f} MiB/sec)').format(
                     synccopy_size_mib / 1024, dltime, dlmibspeed * 8,
                     dlmibspeed))
        end_time = blobxfer.util.datetime_now()
        logger.info('blobxfer end time: {0} (elapsed: {1:.3f} sec)'.format(
            end_time, (end_time - self._start_time).total_seconds()))

    def start(self):
        # type: (SyncCopy) -> None
        """Start the SyncCopy
        :param SyncCopy self: this
        """
        try:
            blobxfer.operations.progress.output_parameters(
                self._general_options, self._spec)
            self._run()
        except (KeyboardInterrupt, Exception) as ex:
            if isinstance(ex, KeyboardInterrupt):
                logger.info(
                    'KeyboardInterrupt detected, force terminating '
                    'processes and threads (this may take a while)...')
            else:
                logger.exception(ex)
            self._wait_for_transfer_threads(terminate=True)
            if not isinstance(ex, KeyboardInterrupt):
                raise
        finally:
            # close resume file
            if self._resume is not None:
                self._resume.close()
