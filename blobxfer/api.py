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
from __future__ import absolute_import, division, print_function  # noqa
from builtins import (  # noqa
    bytes, dict, int, list, object, range, ascii, chr, hex, input,
    next, oct, open, pow, round, super, filter, map, zip
)
# stdlib imports
# non-stdlib imports
# local imports

# clients
from .operations.azure.blob.append import (  # noqa
    create_client as create_append_blob_client
)
from .operations.azure.blob.block import (  # noqa
    create_client as create_block_blob_client
)
from .operations.azure.blob.page import (  # noqa
    create_client as create_page_blob_client
)
from .operations.azure.file import (  # noqa
    create_client as create_file_client
)

# models
from .models.options import (  # noqa
    Timeout as TimeoutOptions,
    Concurrency as ConcurrencyOptions,
    General as GeneralOptions,
    VectoredIo as VectoredIoOptions,
    SkipOn as SkipOnOptions,
    FileProperties as FilePropertiesOptions,
    Download as DownloadOptions,
    SyncCopy as SyncCopyOptions,
    Upload as UploadOptions
)
from .models.download import (  # noqa
    LocalDestinationPath,
    Specification as DownloadSpecification
)
from .models.synccopy import (  # noqa
    Specification as SynccopySpecification
)
from .models.upload import (  # noqa
    LocalSourcePath,
    Specification as UploadSpecification
)

# operations
from .operations.azure import (  # noqa
    StorageCredentials as AzureStorageCredentials,
    DestinationPath as AzureDestinationPath,
    SourcePath as AzureSourcePath
)
from .operations.download import (  # noqa
    Downloader
)
from .operations.synccopy import (  # noqa
    SyncCopy
)
from .operations.upload import (  # noqa
    Uploader
)
