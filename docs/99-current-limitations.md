# blobxfer Current Limitations
Please read this section carefully for any current known limitations to
`blobxfer`.

### SAS Keys (Tokens)
`blobxfer` is fundamentally limited in what operations it can perform
if given a restricted scope SAS token. This is not a limitation with
`blobxfer` itself, but with the permissions that are granted by the SAS
token. The following are a few examples:

* Containers or file shares cannot be created if not given an
  account-level SAS with the appropriate signed resource type.
* Objects cannot be listed within a container or file share if not given
  an account-level SAS or a container-level object SAS. If a
  non-container object-level SAS is provided, remote
  paths associated with these SAS tokens must be a single entity.
* Non-download skip-on processing cannot be performed for SAS tokens
  without sufficient read permission.
* Because policy-based SASes cannot be introspected for permission scope,
  `blobxfer` will assume permissions granting read, write, and list.

### Client-side Encryption
* Client-side encryption is currently only available for block blobs and
Azure Files.
* Azure KeyVault key references are currently not supported.

### Platform-specific
* File attribute store/restore is currently not supported on Windows.

### Resume Support
* Encrypted uploads/downloads cannot currently be resumed as the Python
SHA256 object cannot be pickled.
* Append blobs currently cannot be resumed for upload.

### `stdin` Limitations
* `stdin` uploads with `--mode` set to `page` without the
`--stdin-as-page-blob-size` parameter will allocate a maximum-sized page
blob and then will be resized once the `stdin` source completes. If such
an upload fails, the page blob will remain maximum sized and will be
charged as such; no cleanup is performed if the upload fails.
* `stdin` sources cannot be resumed.
* `stdin` sources cannot be encrypted.
* `stdin` sources cannot be stripe vectorized for upload.
* For optimal performance, `--chunk-size-bytes` should match the "chunk size"
that is being written to `stdin`. For example, if you were using `dd` you
should set the block size (`bs`) parameter to be the same as the
`--chunk-size-bytes` parameter.

### Azure File Limitations
* Empty directories are not created locally when downloading from an Azure
File share which has empty directories.
* Empty directories are not deleted if `--delete` is specified and no files
remain in the directory on the Azure File share.
* Please see [this article](https://msdn.microsoft.com/en-us/library/azure/dn744326.aspx)
for general limitations with Azure File Shares.

### Synccopy Limitations
* Synchronous copy between containers and file shares within the same storage
account must be invoked with a storage key or an account-level SAS token with
access to both services on both the source and destination. Single object
copies are not affected.
* Synchronous copy operations between Azure source and remote paths are
limited to transfers within the same Azure cloud (i.e., the source and
destination `endpoint` must match). For example, you can synchonously copy
within or between storage accounts in Azure Public cloud,
e.g., `core.windows.net` but not between Azure clouds, e.g.,
`core.windows.net` and `core.usgovcloudapi.net`. Single object copies between
clouds can be performed by providing a full source URL as the `--remote-path`.

### Other Limitations
* MD5 is not computed for append blobs.
* Virtual directories in Azure with no characters, e.g. `mycontainer//mydir`
are not supported.
* Downloading of a remote path is based on prefix-matching. Thus a remote path
of `mycontainer/mydir` will also download `mycontainer/mydirfile.txt` and
`mycontainer/mydir1` in addition to `mycontainer/mydir`. To only download
contents of `mycontainer/mydir`, please specify an `--include` filter. For
this example, the include filter would be `--include mydir/*`. Ensure that
the parameter is quoted or shell globbing is disabled. Note that a
remote path of `mycontainer/mydir/` will not work as intended as, internally,
`blobxfer` will strip the trailing slash.
* `/dev/null` or `nul` destinations are not supported.
* Application of access tiers can only be applied to block blobs on either
Blob Storage or General Purpose V2 Storage accounts. Please see
[this article](https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blob-storage-tiers)
for more information.
* A storage object with the same name as a virtual directory is not copied
during a `synccopy` operation.
