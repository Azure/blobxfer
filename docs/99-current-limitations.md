# blobxfer Current Limitations
Please read this section carefully for any current known limitations to
`blobxfer`.

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
* `stdin` uploads without the `--stdin-as-page-blob-size` parameter will
allocate a maximum-sized page blob and then will be resized once the `stdin`
source completes. If the upload fails, the file will remain maximum sized
and will be charged as such; no cleanup is performed if the upload fails.
* `stdin` sources cannot be resumed.
* `stdin` sources cannot be encrypted.
* `stdin` sources cannot be stripe vectorized for upload.
* For optimal performance, `--chunk-size-bytes` should match the "chunk size"
that is being written to `stdin`. For example, if you were using `dd` you
should set the block size (`bs`) parameter to be the same as the
`--chunk-size-bytes` parameter.

### General Azure File Limitations
* Please see [this article](https://msdn.microsoft.com/en-us/library/azure/dn744326.aspx)
for more information.

### Other Limitations
* MD5 is not computed for append blobs.
* Empty directories are not created locally when downloading from an Azure
File share which has empty directories.
* Empty directories are not deleted if `--delete` is specified and no files
remain in the directory on the Azure File share.
* Directories with no characters, e.g. `mycontainer//mydir` are not
supported.
* `/dev/null` or `nul` destinations are not supported.
