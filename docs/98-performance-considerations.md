# blobxfer Performance Considerations
Please read the following carefully regarding considerations that should
be applied with regard to performance and `blobxfer`. Additionally,
please review the
[Azure Storage Scalability and Performance Targets](https://azure.microsoft.com/en-us/documentation/articles/storage-scalability-targets/)
for an overview of general performance targets that apply to Azure Blobs
and File shares.

## Concurrency
* `blobxfer` offers four concurrency knobs. Each one should be tuned for
maximum performance according to your system and network characteristics.
  * Disk threads: concurrency in reading (uploads) and writing (downloads) to
    disk is controlled by the number of disk threads.
  * Transfer threads: concurrency in the number of threads from/to Azure
    Storage is controlled by the number of transfer threads.
  * MD5 processes: computing MD5 for potential omission from transfer due
    to `skip_on` `md5_match` being specified are offloaded to the specified
    number of processors.
  * Crypto processes: decrypting encrypted blobs and files can be offloaded
    to the specified number of processors. Due to the inherent
    non-parallelizable encryption algorithm used, this is ignored for
    encryption (uploads).
* The thread concurrency options (disk and transfer) can be set to a
non-positive number to be automatically set as a multiple of the number of
cores available on the machine.

## Azure File Share Performance
File share performance can be "slow" or become a bottleneck, especially for
file shares containing thousands of files as multiple REST calls must be
performed for each file. Currently, a single file share has a limit of up
to 60 MB/s and 1000 8KB IOPS. Please refer to the
[Azure Storage Scalability and Performance Targets](https://azure.microsoft.com/en-us/documentation/articles/storage-scalability-targets/)
for performance targets and limits regarding Azure Storage File shares.
If scalable high performance is required, consider using Blob storage
instead.

## MD5 Hashing
MD5 hashing will impose some performance penalties to check if the file
should be uploaded or downloaded. For instance, if uploading and the local
file is determined to be different than it's remote counterpart, then the
time spent performing the MD5 comparison is lost.

## Client-side Encryption
Client-side encryption will naturally impose a performance penalty on
`blobxfer` both for uploads (encrypting) and downloads (decrypting) depending
upon the processor speed and number of cores available. Additionally, for
uploads, encryption is not parallelizable and is in-lined with the main
process.

## pyOpenSSL
As of requests 2.6.0 and Python versions < 2.7.9 (i.e., interpreter found on
default Ubuntu 14.04 installations, 16.04 is not affected), if certain
packages are installed, as those found in `requests[security]` then the
underlying urllib3 package will utilize the `ndg-httpsclient` package which
will use `pyOpenSSL`. This will ensure the peers are fully validated. However,
this incurs a rather larger performance penalty. If you understand the
potential security risks for disabling this behavior due to high performance
requirements, you can either remove `ndg-httpsclient` or use `blobxfer` in a
virtualenv environment without the `ndg-httpsclient` package. Python
versions >= 2.7.9 are not affected by this issue.

Additionally, `urllib3` (which `requests` uses) may use `pyOpenSSL` which
may result in exceptions being thrown that are not normalized by `urllib3`.
This may result in exceptions that should be retried, but are not. It is
recommended to upgrade your Python where `pyOpenSSL` is not required for
fully validating peers and such that `blobxfer` can operate without
`pyOpenSSL` in a secure fashion. You can also run `blobxfer` via Docker
or in a virtualenv environment without `pyOpenSSL`.
