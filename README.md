[![Build Status](https://travis-ci.org/Azure/blobxfer.svg?branch=master)](https://travis-ci.org/Azure/blobxfer)
[![Coverage Status](https://coveralls.io/repos/github/Azure/blobxfer/badge.svg?branch=master)](https://coveralls.io/github/Azure/blobxfer?branch=master)
[![PyPI](https://img.shields.io/pypi/v/blobxfer.svg)](https://pypi.python.org/pypi/blobxfer)
[![PyPI](https://img.shields.io/pypi/pyversions/blobxfer.svg)](https://pypi.python.org/pypi/blobxfer)
[![Docker Pulls](https://img.shields.io/docker/pulls/alfpark/blobxfer.svg)](https://hub.docker.com/r/alfpark/blobxfer)
[![Image Layers](https://images.microbadger.com/badges/image/alfpark/blobxfer:latest.svg)](http://microbadger.com/images/alfpark/blobxfer)

# blobxfer
`blobxfer` is an advanced data movement tool and library for Azure Storage
Blob and Files. With `blobxfer` you can copy your files into or out of Azure
Storage with the CLI or integrate the `blobxfer` data movement library into
your own Python scripts.

## Major Features
* Command-line interface (CLI) providing data movement capability to and
from Azure Blob and File Storage
* Standalone library for integration with scripts or other Python packages
* High-performance design with asynchronous transfers and disk I/O
* YAML configuration driven execution support
* Resume support
* Vectored IO support
  * `stripe` mode allows striping a single file across multiple blobs (even
    to multiple storage accounts) to break through single blob or fileshare
    throughput limits
  * `replica` mode allows replication of a file across multiple destinations
    including to multiple storage accounts
* Client-side encryption support
* Support all blob types for both upload and download
* Advanced skip options for rsync-like operations
* Store/restore POSIX filemode and uid/gid
* Support for reading/pipe from `stdin`
* Support for reading from blob snapshots
* Configurable one-shot block upload support
* Configurable chunk size for both upload and download
* Automatic block blob size adjustment for uploading
* Automatic uploading of VHD/VHDX files as page blobs
* Include and exclude filtering support
* Rsync-like delete support
* No clobber support in either direction
* File logging support

## Installation
`blobxfer` is on [PyPI](https://pypi.python.org/pypi/blobxfer) and on
[Docker Hub](https://hub.docker.com/r/alfpark/blobxfer/). Please refer to
the [installation guide](https://github.com/Azure/blobxfer/blob/master/docs/01-installation.md)
on how to install `blobxfer`.

## Documentation
Please refer to the [blobxfer Documentation](https://github.com/Azure/blobxfer/blob/master/docs)
for more details and usage information.

## Change Log
For recent changes, please refer to the
[CHANGELOG.md](https://github.com/Azure/blobxfer/blob/master/CHANGELOG.md)
file.

------------------------------------------------------------------------

This project has adopted the
[Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the
[Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [<opencode@microsoft.com>](mailto:opencode@microsoft.com) with any
additional questions or comments.
