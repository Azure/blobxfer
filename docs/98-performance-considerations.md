# blobxfer Performance Considerations
Please read the following carefully regarding considerations that should
be applied with regard to performance and `blobxfer`. Additionally,
please review the
[Azure Storage Scalability and Performance Targets](https://azure.microsoft.com/en-us/documentation/articles/storage-scalability-targets/)
for an overview of general performance targets that apply to Azure Blobs,
File shares and Storage Account types (GRS, LRS, ZRS, etc).

## Concurrency
* `blobxfer` offers four concurrency knobs. Each one should be tuned for
maximum performance according to your system and network characteristics.
    * Disk threads: concurrency in reading (uploads) and writing (downloads)
      to disk is controlled by the number of disk threads.
    * Transfer threads: concurrency in the number of threads transferring
      from/to Azure Storage is controlled by the number of transfer threads.
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
* For uploads, there should be a sufficient number of disk threads to ensure
that all transfer threads have work to do. For downloads, there should be
sufficient number of disk threads to write data to disk so transfer threads
are not artificially blocked.

## Chunk Sizing
Chunk sizing refers to the `chunk_size_bytes` option and the meaning of which
varies upon the context of uploading or downloading.

### Uploads
For uploads, chunk sizes correspond to the maximum amount of data to transfer
with a single request. The Azure Storage service imposes maximums depending
upon the type of entity that is being written. For block blobs, the maximum
is 100MiB (although you may "one-shot" up to 256MiB). For page blobs, the
maximum is 4MiB. For append blobs, the maximum is 4MiB. For Azure Files,
the maximum is 4MiB.

For block blobs, setting the chunk size to something greater than 4MiB will
not only allow you larger file sizes (recall that the maximum number of
blocks for a block blob is 50000, thus at 100MiB blocks, you can create a
4.768TiB block blob object) but will allow you to amortize larger portions of
data transfer over each request/response overhead. `blobxfer` can
automatically select the proper block size given your file, but will not
automatically tune the chunk size as that depends upon your system and
network characteristics.

### Downloads
For downloads, chunk sizes correspond to the maximum amount of data to
request from the server for each request. It is important to keep a balance
between the chunk size and the number of in-flight operations afforded by
the `transfer_threads` concurrency control. `blobxfer` does not automatically
tune this (but can automatically set it to a value that should work for
most situations) due to varying system and network conditions.

Additionally, disk write performance is typically lower than disk read
performance so you need to ensure that the number of `disk_threads` is not
set to a very large number to prevent thrashing and highly random write
patterns.

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
file is determined to be different than its remote counterpart, then the
time spent performing the MD5 comparison is effectively "lost."

## Client-side Encryption
Client-side encryption will naturally impose a performance penalty on
`blobxfer` both for uploads (encrypting) and downloads (decrypting) depending
upon the processor speed and number of cores available. Additionally, for
uploads, encryption is not parallelizable within an object and is in-lined
with the main process.

## Resume Files (Databases)
Enabling resume support may slightly impact performance as a key-value shelve
for bookkeeping is kept on disk and is updated frequently.

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
