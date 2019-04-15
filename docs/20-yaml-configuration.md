# blobxfer YAML Configuration
`blobxfer` accepts YAML configuration files to drive the transfer. YAML
configuration files are specified with the `--config` option to any
`blobxfer` command.

For an in-depth explanation of each option or the associated default value,
please see the [CLI Usage](10-cli-usage.md) documentation for the
corresponding CLI option.

## Schema
The `blobxfer` YAML schema consists of distinct "sections". The following
sub-sections will describe each. You can combine all sections into the
same YAML file if desired as `blobxfer` will only read the required sections
to execute the specified command.

You can view a complete sample YAML configuration [here](sample_config.yaml).
Note that the sample configuration file is just a sample and may not contain
all possible options.

#### Configuration Sections
1. [`version`](#version)
2. [`azure_storage`](#azure-storage)
3. [`options`](#options)
4. [`download`](#download)
5. [`upload`](#upload)
6. [`synccopy`](#synccopy)

### <a name="version"></a>`version`
The `version` property specifies the version of the `blobxfer` YAML
configuration schema to use. This property is required.

```yaml
version: 1
```

* `version` specifies the `blobxfer` YAML configuration schema to use.
Currently the only valid value is `1`.

### <a name="azure-storage"></a>`azure_storage`
The `azure_storage` section specifies Azure Storage credentials that will
be referenced for any transfer while processing the YAML file. This section
is required.

```yaml
azure_storage:
  endpoint: core.windows.net
  accounts:
    mystorageaccount0: ABCDEF...
    mystorageaccount1: ?se...
```

* `endpoint` specifies for which endpoint to connect to with Azure Storage.
Generally this can be omitted if using Public Azure regions.
* `accounts` is a dictionary of storage account names and either a
storage account key or a shared access signature token. Note that if you
are downloading a striped blob (Vectored IO), then all storage accounts for
which the blob is striped to must be populated in this list.

### <a name="options"></a>`options`
The `options` section specifies general options that may be applied across
all other sections in the YAML configuration.

```yaml
options:
  log_file: /path/to/blobxfer.log
  enable_azure_storage_logger: false
  resume_file: /path/to/resumefile.db
  progress_bar: true
  quiet: false
  dry_run: false
  verbose: true
  timeout:
    connect: null
    read: null
    max_retries: null
  concurrency:
    md5_processes: 2
    crypto_processes: 2
    disk_threads: 16
    transfer_threads: 32
  proxy:
    host: myproxyhost:6000
    username: proxyuser
    password: abcd...
```

* `log_file` is the location of the log file to write to
* `enable_azure_storage_logger` controls the Azure Storage logger output
* `resume_file` is the location of the resume database to create
* `progress_bar` controls display of a progress bar output to the console
* `quiet` controls quiet mode
* `dry_run` will perform a dry run
* `verbose` controls if verbose logging is enabled
* `timeout` is a dictionary of timeout values in seconds
    * `connect` is the connect timeout to apply to a request
    * `read` is the read timeout to apply to a request
    * `max_retries` is the maximum number of retries for a request
* `concurrency` is a dictionary of concurrency limits
    * `md5_processes` is the number of MD5 offload processes to create for
      MD5 comparison checking
    * `crypto_processes` is the number of decryption offload processes to
      create
    * `disk_threads` is the number of threads for disk I/O
    * `transfer_threads` is the number of threads for network transfers
* `proxy` defines an HTTP proxy to use, if required to connect to the
Azure Storage endpoint
    * `host` is the IP:Port of the HTTP Proxy
    * `username` is the username login for the proxy, if required
    * `password` is the password for the username for the proxy, if required

### <a name="download"></a>`download`
The `download` section specifies download sources and destination. Note
that `download` refers to a list of objects, thus you may specify as many
of these sub-configuration blocks on the `download` property as you need.
When the `download` command with the YAML config is specified, the list
is iterated and all specified sources are downloaded.

```yaml
download:
    - source:
      - mystorageaccount0: mycontainer
      - mystorageaccount1: someothercontainer/vpath
      destination: /path/to/store/downloads
      include:
      - "*.txt"
      - "*.bxslice-*"
      exclude:
      - "*.bak"
      options:
          check_file_md5: true
          chunk_size_bytes: 16777216
          delete_extraneous_destination: false
          max_single_object_concurrency: 8
          mode: auto
          overwrite: true
          recursive: true
          rename: false
          restore_file_properties:
              attributes: true
              lmt: true
          rsa_private_key: myprivatekey.pem
          rsa_private_key_passphrase: myoptionalpassword
          strip_components: 1
          skip_on:
              filesize_match: false
              lmt_ge: false
              md5_match: true
    - source:
      # next if needed...
```

* `source` is a list of storage account to remote path mappings
* `destination` is the local resource path
* `include` is a list of include patterns
* `exclude` is a list of exclude patterns
* `options` are download-specific options
    * `check_file_md5` will integrity check downloaded files using the stored
      MD5
    * `chunk_size_bytes` is the maximum amount of data to download per request
    * `delete_extraneous_destination` will cleanup any files locally that are
      not found on the remote. Note that this interacts with include and
      exclude filters.
    * `max_single_object_concurrency` is the maximum number of concurrent
      transfers per object
    * `mode` is the operating mode
    * `overwrite` specifies clobber behavior
    * `recursive` specifies if remote paths should be recursively searched for
      entities to download
    * `rename` will rename a single entity source path to the `destination`
    * `restore_file_properties` restores the following file properties if
      enabled
        * `attributes` will restore POSIX file mode and ownership if stored
          on the entity metadata
        * `lmt` will restore the last modified time of the file
    * `rsa_private_key` is the RSA private key PEM file to use to decrypt
      encrypted blobs or files
    * `rsa_private_key_passphrase` is the RSA private key passphrase, if
      required
    * `strip_components` is the number of leading path components to strip
      from the remote path
    * `skip_on` are skip on options to use
        * `filesize_match` skip if file size match
        * `lmt_ge` skip if local file has a last modified time greater than or
          equal to the remote file
        * `md5_match` skip if MD5 match

### <a name="upload"></a>`upload`
The `upload` section specifies upload sources and destinations. Note
that `upload` refers to a list of objects, thus you may specify as many
of these sub-configuration blocks on the `upload` property as you need.
When the `upload` command with the YAML config is specified, the list
is iterated and all specified sources are uploaded.

```yaml
upload:
    - source:
      - /path/to/hugefile1
      - /path/to/hugefile2
      destination:
      - mystorageaccount0: mycontainer/vdir
      - mystorageaccount1: someothercontainer/vdir2
      include:
      - "*.bin"
      exclude:
      - "*.tmp"
      options:
          mode: auto
          access_tier: null
          chunk_size_bytes: 0
          delete_extraneous_destination: true
          one_shot_bytes: 33554432
          overwrite: true
          recursive: true
          rename: false
          rsa_public_key: mypublickey.pem
          skip_on:
              filesize_match: false
              lmt_ge: false
              md5_match: true
          stdin_as_page_blob_size: 0
          store_file_properties:
              attributes: true
              cache_control: 'max-age=3600'
              content_type: 'text/javascript; charset=utf-8'
              md5: true
          strip_components: 1
          vectored_io:
              stripe_chunk_size_bytes: 1000000
              distribution_mode: stripe
    - source:
      # next if needed...
```

* `source` is a list of local resource paths
* `destination` is a list of storage account to remote path mappings
* `include` is a list of include patterns
* `exclude` is a list of exclude patterns
* `options` are upload-specific options
    * `mode` is the operating mode
    * `access_tier` is the access tier to set for the object. If not set,
      the default access tier for the storage account is inferred.
    * `chunk_size_bytes` is the maximum amount of data to upload per request.
      This corresponds to the block size for block and append blobs, page size
      for page blobs, and the file chunk for files. Only block blobs can have
      a block size of up to 100MiB, all others have a maximum of 4MiB.
    * `delete_extraneous_destination` will cleanup any files remotely that are
      not found on locally. Note that this interacts with include and
      exclude filters.
    * `one_shot_bytes` is the size limit to upload block blobs in a single
      request.
    * `overwrite` specifies clobber behavior
    * `recursive` specifies if local paths should be recursively searched for
      files to upload
    * `rename` will rename a single entity destination path to a single
      `source`
    * `rsa_public_key` is the RSA public key PEM file to use to encrypt files
    * `skip_on` are skip on options to use
        * `filesize_match` skip if file size match
        * `lmt_ge` skip if remote file has a last modified time greater than
          or equal to the local file
        * `md5_match` skip if MD5 match
    * `stdin_as_page_blob_size` is the page blob size to preallocate if the
      amount of data to be streamed from stdin is known beforehand and the
      `mode` is `page`
    * `store_file_properties` stores the following file properties if enabled
        * `attributes` will store POSIX file mode and ownership
        * `cache_control` sets the CacheControl property
        * `content_type` sets the ContentType property
        * `md5` will store the MD5 of the file
    * `strip_components` is the number of leading path components to strip
      from the local path
    * `vectored_io` are the Vectored IO options to apply to the upload
        * `stripe_chunk_size_bytes` is the stripe width for each chunk if
          `stripe` `distribution_mode` is selected
        * `distribution_mode` is the Vectored IO mode to use which can be
          one of:
            * `disabled` will disable Vectored IO
            * `replica` which will replicate source files to target
              destinations on upload. Note that more than one destination
              should be specified.
            * `stripe` which will stripe source files to target destinations
              on upload. If more than one destination is specified, striping
              occurs in round-robin order amongst the destinations listed.

### <a name="synccopy"></a>`synccopy`
The `synccopy` section specifies synchronous copy sources and destinations.
Note that `synccopy` refers to a list of objects, thus you may specify as many
of these sub-configuration blocks on the `synccopy` property as you need.
When the `synccopy` command with the YAML config is specified, the list
is iterated and all specified sources are synchronously copied.

```yaml
synccopy:
    - source:
        - mystorageaccount0: mycontainer
      destination:
        - mystorageaccount0: othercontainer
        - mystorageaccount1: mycontainer
      include:
        - "*.bin"
      exclude:
        - "*.tmp"
      options:
          mode: auto
          dest_mode: auto
          access_tier: null
          delete_extraneous_destination: true
          overwrite: true
          recursive: true
          rename: false
          skip_on:
              filesize_match: false
              lmt_ge: false
              md5_match: true
```

* `source` is a list of storage account to remote path mappings. All sources
are copied to each destination specified.
* `destination` is a list of storage account to remote path mappings
* `include` is a list of include patterns
* `exclude` is a list of exclude patterns
* `options` are synccopy-specific options
    * `mode` is the source mode
    * `dest_mode` is the destination mode
    * `access_tier` is the access tier to set for the object. If not set,
      the default access tier for the storage account is inferred.
    * `delete_extraneous_destination` will cleanup any files in remote
      destinations that are not found in the remote sources. Note that this
      interacts with include and exclude filters.
    * `overwrite` specifies clobber behavior
    * `recursive` specifies if source remote paths should be recursively
      searched for files to copy
    * `rename` will rename a single remote source entity to the remote
      destination path
    * `skip_on` are skip on options to use
        * `filesize_match` skip if file size match
        * `lmt_ge` skip if source file has a last modified time greater
          than or equal to the destination file
        * `md5_match` skip if MD5 match
