# blobxfer Vectored I/O
`blobxfer` supports Vectored I/O (scatter/gather) which can help alleviate
problems associated with
[single blob or single fileshare throughput limits](https://docs.microsoft.com/en-us/azure/storage/storage-scalability-targets).
Additionally, `blobxfer` has the ability to replicate a single source to
multiple destinations to allow for increased resiliency or throughput for
consumption later.

## Distribution Modes
`blobxfer` supports two distribution modes: `replica` and `stripe`. The
following sections describe each.

### Replica
`replica` mode replicates an entire file (or set of files) across all
specified destinations. This allows for multiple backups, resiliency,
and potentially increased download throughput later if the clients understand
how to download from multiple sources.

The logic is fairly simple in how this is accomplished. Each source file
has portions of the file read from disk, buffered in memory and then
replicated across all specified destinations.

```
                       Whole File             +---------------------+
                       Replication            |                     |
             +------------------------------> |  Destination 0:     |
             |                                |  Storage Account A  |
             |                                |                     |
             |                                +---------------------+
             |
             |
+------------+---------------+  Whole File    +---------------------+
|                            |  Replication   |                     |
|  10 GiB VHD on Local Disk  +--------------> |  Destination 1:     |
|                            |                |  Storage Account B  |
+------------+---------------+                |                     |
             |                                +---------------------+
             |
             |
             |                                +---------------------+
             |         Whole File             |                     |
             |         Replication            |  Destination 2:     |
             +------------------------------> |  Storage Account C  |
                                              |                     |
                                              +---------------------+
```

In order to take advantage of `replica` Vectored IO, you must use a YAML
configuration file to define multiple destinations.

### Stripe
`stripe` mode will splice a file into multiple chunks and scatter these
chunks across destinations specified. These destinations can be different
a single or multiple containers within the same storage account or even
containers distributed across multiple storage accounts if single storage
account bandwidth limits are insufficient.

`blobxfer` will slice the source file into multiple chunks where the
`stripe_chunk_size_bytes` is the stripe width of each chunk. This parameter
will allow you to effectively control how many blobs/files are created on
Azure. `blobxfer` will then round-robin through all of the destinations
specified to store the slices. Information required to reconstruct the
original file is stored on the blob or file metadata. It is important to
keep this metadata in-tact or reconstruction will fail.

```
                                                     +---------------------+
                                                     |                     | <-----------------------------------+
                                                     |  Destination 1:     |                                     |
                                                     |  Storage Account B  | <---------------------+             |
                                                     |                     |                       |             |
                                                     +---------------------+ <-------+             |             |
                                                                                     |             |             |
                                                         ^             ^             |             |             |
                                                         |             |             |             |             |
                                 1 GiB Stripe            |             |             |             |             |
+-----------------------------+  Width        +------+---+--+------+---+--+------+---+--+------+---+--+------+---+--+
|                             |               |      |      |      |      |      |      |      |      |      |      |
|  10 GiB File on Local Disk  | +-----------> |  D0  |  D1  |  D0  |  D1  |  D0  |  D1  |  D0  |  D1  |  D0  |  D1  |
|                             |               |      |      |      |      |      |      |      |      |      |      |
+-----------------------------+  10 Vectored  +---+--+------+---+--+------+---+--+------+---+--+------+---+--+------+
                                 Slices           |             |             |             |             |
                                                  |             |             |             |             |
                                                  |             v             |             |             |
                                                  |                           |             |             |
                                                  +> +---------------------+ <+             |             |
                                                     |                     |                |             |
                                                     |  Destination 0:     | <--------------+             |
                                                     |  Storage Account A  |                              |
                                                     |                     | <----------------------------+
                                                     +---------------------+
```

In order to take advantage of `stripe` Vectored IO across multiple
destinations, you must use a YAML configuration file. Additionally, when
downloading a striped blob, you must specify all storage account locations
of the striped blob in the `azure_storage` section of your YAML
configuration file.
