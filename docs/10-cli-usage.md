# blobxfer Command-Line Usage

## TODO


### General Notes
* `blobxfer` does not take any leases on blobs or containers. It is up to the
user to ensure that blobs are not modified while download/uploads are being
performed.
* No validation is performed regarding container and file naming and length
restrictions.
* `blobxfer` will attempt to download from blob storage as-is. If the source
filename is incompatible with the destination operating system, then failure
may result.
* When using SAS, the SAS key must be a container- or share-level SAS if
performing recursive directory upload or container/file share download.
* If uploading via service-level SAS keys, the container or file share must
already be created in Azure storage prior to upload. Account-level SAS keys
with the signed resource type of `c` (i.e., container-level permission) is
required for to allow conatiner or file share creation.
* When uploading files as page blobs, the content is page boundary
byte-aligned. The MD5 for the blob is computed using the final aligned data
if the source is not page boundary byte-aligned. This enables these page
blobs or files to be skipped during subsequent download or upload with the
appropriate `skip_on` option, respectively.
* Globbing of wildcards must be disabled by your shell (or properly quoted)
during invoking `blobxfer` such that include and exclude patterns can be
read verbatim without the shell expanding the wildcards.
* The `--delete` operates similarly to `--delete-after` in rsync. Please
note that this option interacts with `--include` and `--exclude` filters.
