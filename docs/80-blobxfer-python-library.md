# `blobxfer` Python Data Movement Library
`blobxfer` is comprised of two main components, the CLI tool and the data
movement library. The `blobxfer` CLI tool is built on top of the `blobxfer`
data movement library.

## `blobxfer` Python Package structure
The `blobxfer` Python package is laid out as follows:

```
├── blobxfer
│   ├── models
│   └── operations
│       └── azure
│           └── blob
├── cli
...
```

The `blobxfer` CLI tool is entirely contained in the `cli` directory and
is thus not part of the `blobxfer` data movement library. To import the
`blobxfer` data movement library, you would simply perform `import` statements
such as `import blobxfer`.

## High-Level Operations: `blobxfer.api`
The high-level `blobxfer` API is found in the `blobxfer.api` module. This
module exposes each of the operations: `Downloader`, `SyncCopy` and
`Uploader`.

These high-level operations classes allow you to input various options for
each type of operation and allows the `blobxfer` data movement library to
do the rest without having to construct each of the pieces yourself. For
example, to download a set of blobs, you would invoke the `Downloader`
similar to the following:

```python
# Downloader Example

import blobxfer.api


# construct general options
general_options = blobxfer.api.GeneralOptions(...)

# construct download options
download_options = blobxfer.api.DownloadOptions(...)

# construct skip on options
skip_on_options = blobxfer.api.SkipOnOptions(...)

# construct local destination path
local_destination_path = blobxfer.api.LocalDestinationPath(...)

# construct specification
specification = blobxfer.api.DownloadSpecification(
    download_options,
    skip_on_options,
    local_destination_path)

# construct credentials
credentials = blobxfer.api.AzureStorageCredentials(general_options)
credentials.add_storage_account(...)

# construct Azure source paths and add it to specification
asp = blobxfer.api.AzureSourcePath()
asp.add_path_with_storeage_account(...)
specification.add_azure_source_path(asp)

# execute downloader
downloader = blobxfer.api.Downloader(
    general_options,
    credentials,
    specification)
downloader.start()
```

## Canonical Example of Library Use: `cli`
As the `blobxfer` CLI is built on top of the `blobxfer` data movement library,
examining the contents of the
[`cli` directory](https://github.com/Azure/blobxfer/tree/master/cli) will
provide you with a code sample of how to utilize the `blobxfer` data movement
library for your own Python programs and modules.
