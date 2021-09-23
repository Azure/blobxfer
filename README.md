[![Build Status](https://azurebatch.visualstudio.com/blobxfer/_apis/build/status/blobxfer-CI)](https://azurebatch.visualstudio.com/blobxfer/_build/latest?definitionId=12)
[![Build status](https://ci.appveyor.com/api/projects/status/qgth9p7jlessgp5i/branch/master?svg=true)](https://ci.appveyor.com/project/alfpark/blobxfer)
[![codecov](https://codecov.io/gh/Azure/blobxfer/branch/master/graph/badge.svg)](https://codecov.io/gh/Azure/blobxfer)
[![PyPI](https://img.shields.io/pypi/v/blobxfer.svg)](https://pypi.python.org/pypi/blobxfer)

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
* Supports ingress, egress and synchronization of entire directories,
containers and file shares
* YAML configuration driven execution support
* Fine-grained resume support including resuming a broken operation
within a file or object
* Vectored IO support
    * `stripe` mode allows striping a single file across multiple blobs (even
      to multiple storage accounts) to break through single blob or fileshare
      throughput limits
    * `replica` mode allows replication of a file across multiple destinations
      including to multiple storage accounts
* Synchronous copy with cross-mode (object transform) replication support
    * Leverages server-side copies by default
    * Arbitrary URL copy support
* Client-side encryption support
* Support all Azure Blob types and Azure Files for both upload and download
* Advanced skip options for rsync-like operations
* Store/restore POSIX filemode and uid/gid
* Support reading/pipe from `stdin` including to page blob destinations
* Support reading from blob and file share snapshots for downloading and
synchronous copy
* Support for setting access tier on objects for uploading and synchronous
copy
* Configurable one-shot block upload support
* Configurable chunk size for both upload and download
* Automatic block size selection for block blob uploading
* Automatic uploading of VHD/VHDX files as page blobs
* Include and exclude filtering support
* Rsync-like delete support
* No clobber support in either direction
* Automatic content type tagging
* Support for setting the Cache Control property of blobs and files
* File logging support
* Support for HTTP proxies

## Installation
There are three ways to install `blobxfer`:

* `blobxfer` Python package from [PyPI](https://pypi.python.org/pypi/blobxfer)
* Pre-built binaries available under [Releases](https://github.com/Azure/blobxfer/releases)
* Docker images are available for both Linux and Windows platforms on the
[Microsoft Container Registry](https://hub.docker.com/_/microsoft-blobxfer)

Please refer to the
[installation guide](http://blobxfer.readthedocs.io/en/latest/01-installation/)
for more information on how to install `blobxfer`.

## Documentation
Please refer to the [`blobxfer` documentation](http://blobxfer.readthedocs.io/)
for more details and usage information.

## Change Log
Please see the
[Change Log](http://blobxfer.readthedocs.io/en/latest/CHANGELOG/)
for project history.

## Support
This project is community supported and not officially supported by Microsoft.
There is no defined SLA for addressing features, issues, and bugs which are
exclusively serviced via GitHub issues. For tools officially supported by
Microsoft please refer to this
[documentation](https://docs.microsoft.com/azure/storage/common/storage-choose-data-transfer-solution).

* * *
Please see this project's [Code of Conduct](CODE_OF_CONDUCT.md) and
[Contributing](CONTRIBUTING.md) guidelines.
