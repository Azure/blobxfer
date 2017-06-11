# blobxfer Current Limitations
Please read this section carefully for any current known limitations to
`blobxfer`.

### Client-side Encryption
* Client-side encryption is currently only available for block blobs and
Azure Files.
* `stdin` sources cannot be encrypted.
* Azure KeyVault key references are currently not supported.

### Platform-specific
* File attribute store/restore is currently not supported on Windows.

### Resume Support
* Encrypted uploads/downloads cannot currently be resumed as the Python
SHA256 object cannot be pickled.
* Append blobs currently cannot be resumed for upload.

### Other Limitations
* MD5 is not computed for append blobs.
* Empty directories are not created locally when downloading from an Azure
File share which has empty directories.
* Empty directories are not deleted if `--delete` is specified and no files
remain in the directory on the Azure File share.
* Directories with no characters, e.g. `mycontainer//mydir` are not
supported.
* `/dev/null` or `nul` destinations are not supported.
