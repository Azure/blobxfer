# blobxfer Command-Line Usage
`blobxfer` operates using a command followed by options. Each
command will be detailed along with all options available.

### Quick Navigation
1. [Commands](#commands)
2. [Options](#options)
3. [Example Invocations](#examples)
4. [General Notes](#general-notes)

## <a name="commands"></a>Commands
### `download`
Downloads a remote Azure path, which may contain many resources, to the
local machine. This command requires at the minimum, the following options:
* `--storage-account`
* `--remote-path`
* `--local-path`

Additionally, an authentication option for the storage account is required.
Please see the Authentication sub-section below under Options.

### `upload`
Uploads a local path to a remote Azure path. The local path may contain
many resources on the local machine. This command requires at the minimum,
the following options:
* `--local-path`
* `--storage-account`
* `--remote-path`

Additionally, an authentication option for the storage account is required.
Please see the Authentication sub-section below under Options.

If piping from `stdin`, `--local-path` should be set to `-` as per
convention.

### `synccopy`
TODO: not yet implemented.

## <a name="options"></a>Options
### General
* `--config` specifies the YAML configuration file to use. This can be
optionally provided through an environment variable `BLOBXFER_CONFIG_FILE`.
* `--chunk-size-bytes` is the chunk size in bytes. For downloads, this
is the maximum length of data to transfer per request. For uploads, this
corresponds to one of block size for append and block blobs, page size for
page blobs, or file chunk for files. Only block blobs can have a block size
of up to 100MiB, all others have a maximum of 4MiB.
* `--file-attributes` or `--no-file-attributes` controls if POSIX file
attributes (mode and ownership) should be stored or restored. Note that to
restore uid/gid, `blobxfer` must be run as root or under sudo.
* `--file-md5` or `--no-file-md5` controls if the file MD5 should be computed.
* `--local-path` is the local resource path. Set to `-` if piping from
`stdin`.
* `--log-file` specifies the log file to write to. This must be specified
for a progress bar to be output to console.
* `--mode` is the operating mode. The default is `auto` but may be set to
`append`, `block`, `file`, or `page`. If specified with the `upload`
command, then all files will be uploaded as the specified `mode` type. If
`mode` is `auto` while uploading, then `.vhd` and `.vhdx` files are
uploaded automatically as page blobs while all other files are uploaded
as block blobs. If specified with `download`, then only remote entities
with that `mode` type are downloaded. Note that `file` should be specified
for the `mode` if interacting with Azure File shares.
* `--overwrite` or `--no-overwrite` controls clobber semantics at the
destination.
* `--progress-bar` or `--no-progress-bar` controls if a progress bar is
output to the console. `--log-file` must be specified for a progress bar
to be output.
* `--recursive` or `--no-recursive` controls if the source path should be
recursively uploaded or downloaded.
* `--remote-path` is the remote Azure path. This path must contain the
Blob container or File share at the begining, e.g., `mycontainer/vdir`
* `--resume-file` specifies the resume file to write to or read from.
* `--timeout` is the integral timeout value in seconds to use.
* `-h` or `--help` can be passed at every command level to receive context
sensitive help.
* `-v` will output verbose messages including the configuration used

### Authentication
`blobxfer` supports both Storage Account access keys and Shared Access
Signature (SAS) tokens. One type must be supplied with all commands in
order to successfully authenticate against Azure Storage. These options are:
* `--storage-account-key` is the storage account access key. This can be
optionally provided through an environment variable
`BLOBXFER_STORAGE_ACCOUNT_KEY` instead.
* `--sas` is a shared access signature (sas) token. This can can be
optionally provided through an environment variable `BLOBXFER_SAS` instead.

### Concurrency
Please see the [performance considerations](98-performance-considerations.md)
document for more information regarding concurrency options.
* `--crypto-processes` is the number of decryption offload processes to spawn.
`0` will in-line the decryption routine with the main thread.
* `--disk-threads` is the number of threads to create for disk I/O.
* `--md5-processes` is the number of MD5 offload processes to spawn for
comparing files with `skip_on` `md5_match`.
* `--transfer-threads` is the number of threads to create for transferring
to/from Azure Storage.

### Connection
* `--endpoint` is the Azure Storage endpoint to connect to; the default is
Azure Public regions, or `core.windows.net`.
* `--storage-account` specifies the storage account to use. This can be
optionally provided through an environment variable `BLOBXFER_STORAGE_ACCOUNT`
instead.

### Encryption
* `--rsa-private-key` is the RSA private key in PEM format to use. This can
be provided for uploads but must be specified to decrypt encrypted remote
entities for downloads. This can be optionally provided through an environment
variable `BLOBXFER_RSA_PRIVATE_KEY`.
* `--rsa-private-key-passphrase` is the RSA private key passphrase. This can
be optionally provided through an environment variable
`BLOBXFER_RSA_PRIVATE_KEY_PASSPHRASE`.
* `--rsa-public-key` is the RSA public key in PEM format to use. This
can only be provided for uploads. This can be optionally provided through an
environment variable `BLOBXFER_RSA_PUBLIC_KEY`.

### Filtering
* `--exclude` is an exclude pattern to use; this can be specified multiple
times. Exclude patterns are applied after include patterns. If both an exclude
and an include pattern match a target, the target is excluded.
* `--include` is an include pattern to use; this can be specified multiple
times

### Skip On
* `--skip-on-filesize-match` will skip the transfer action if the filesizes
match between source and destination. This should not be specified for
encrypted files.
* `--skip-on-lmt-ge` will skip the transfer action:
  * On upload if the last modified time of the remote file is greater than
    or equal to the local file.
  * On download if the last modified time of the local file is greater than
    or equal to the remote file.
* `--skip-on-md5-match` will skip the transfer action if the MD5 hash match
between source and destination. This can be transparently used through
encrypted files that have been uploaded with `blobxfer`.

### Vectored IO
Please see the [Vectored IO](30-vectored-io.md) document for more information
regarding Vectored IO operations in `blobxfer`.
* `--distribution-mode` is the Vectored IO distribution mode
  * `disabled` which is default (no Vectored IO)
  * `replica` which will replicate source files to target destinations on
    upload. Note that replicating across multiple destinations will require
    a YAML configuration file.
  * `stripe` which will stripe source files to target destinations on upload.
    Note that striping across multiple destinations will require a YAML
    configuration file.
* `--stripe-chunk-size-bytes` is the stripe chunk width for stripe-based
Vectored IO operations

### Other
* `--delete` deletes extraneous files at the remote destination path on
uploads and at the local resource on downloads. This actions occur after the
transfer has taken place.
* `--one-shot-bytes` controls the number of bytes to "one shot" a block
Blob upload. The maximum value that can be specified is 256MiB. This may
be useful when using account-level SAS keys and enforcing non-overwrite
behavior.
* `--rename` renames a single file upload or download to the target
destination or source path, respectively.
* `--strip-components N` will strip the leading `N` components from the
file path. The default is `1`.

## <a name="examples"></a>Example Invocations
### `download` Examples
#### Download an Entire Encrypted Blob Container to Current Working Directory
```shell
blobxfer download --storage-account mystorageaccount --sas "mysastoken" --remote-path mycontainer --local-path . --rsa-private-key ~/myprivatekey.pem
```

#### Download an Entire File Share to Designated Path and Skip On Filesize Matches
```shell
blobxfer download --mode file --storage-account mystorageaccount --storage-account-key "myaccesskey" --remote-path myfileshare --local-path /my/path --skip-on-filesize-match
```

#### Download only Page Blobs in Blob Container Virtual Directory Non-recursively and Cleanup Local Path to Match Remote Path
```shell
blobxfer download --mode page --storage-account mystorageaccount --storage-account-key "myaccesskey" --remote-path mycontainer --local-path /my/pageblobs --no-recursive --delete
```

#### Resume Incomplete Downloads Matching an Include Pattern and Log to File and Restore POSIX File Attributes
```shell
blobxfer download --storage-account mystorageaccount --storage-account-key "myaccesskey" --remote-path mycontainer --local-path . --include '*.bin' --resume-file myresumefile.db --log-file blobxfer.log --file-attributes
```

#### Download a Blob Snapshot
```shell
blobxfer download --storage-account mystorageaccount --sas "mysastoken" --remote-path "mycontainer/file.bin?snapshot=2017-04-20T02:12:49.0311708Z" --local-path .
```

#### Download using a YAML Configuration File
```shell
blobxfer download --config myconfig.yaml
```

### `upload` Examples
#### Upload Current Working Directory as Encrypted Block Blobs Non-recursively
```shell
blobxfer upload --storage-account mystorageaccount --sas "mysastoken" --remote-path mycontainer --local-path . --no-recursive --rsa-public-key ~/mypubkey.pem
```

#### Upload Specific Path Recursively to a File Share, Store File MD5 and POSIX File Attributes to a File Share and Exclude Some Files
```shell
blobxfer upload --mode file --storage-account mystorageaccount --sas "mysastoken" --remote-path myfileshare --local-path . --file-md5 --file-attributes --exclude '*.bak'
```

#### Upload Single File with Resume and Striped Vectored IO into 512MiB Chunks
```shell
blobxfer upload --storage-account mystorageaccount --sas "mysastoken" --remote-path mycontainer --local-path /some/huge/file --resume-file hugefileresume.db --distribution-mode stripe --stripe-chunk-size-bytes 536870912
```

#### Upload Specific Path but Skip On Any MD5 Matches, Store File MD5 and Cleanup Remote Path to Match Local Path
```shell
blobxfer upload --storage-account mystorageaccount --sas "mysastoken" --remote-path mycontainer --local-path /my/path --file-md5 --skip-on-md5-match --delete
```

#### Upload From Piped `stdin`
```shell
curl -fSsL https://some.uri | blobxfer upload --storage-account mystorageaccount --sas "mysastoken" --remote-path mycontainer --local-path -
```

#### Upload using a YAML Configuration File
```shell
blobxfer upload --config myconfig.yaml
```

### `synccopy` Examples
TODO: not implemented yet.

## <a name="general-notes"></a>General Notes
* `blobxfer` does not take any leases on blobs or containers. It is up to the
user to ensure that blobs are not modified while download/uploads are being
performed.
* No validation is performed regarding container and file naming and length
restrictions.
* `blobxfer` will attempt to download from blob storage as-is. If the source
filename is incompatible with the destination operating system, then failure
may result.
* When using SAS, the SAS key must have container- or share-level permissions
if performing recursive directory upload or container/file share download.
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
