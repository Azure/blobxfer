# blobxfer Client-side Encryption Notes
Please read the following carefully regarding client-side encryption support
in `blobxfer`. Additionally, current limitations for client-side encryption
can be found [here](99-current-limitations.md).

* Encryption is performed using AES256-CBC. MACs are generated using
HMAC-SHA256.
* All required information regarding the encryption process is stored on
each blob's `encryptiondata` and `encryptiondata_authentication` metadata
fields. These metadata entries are used on download to configure the proper
download parameters for the decryption process as well as to authenticate
the `encryptiondata` metadata and the encrypted entity. Encryption metadata
set by `blobxfer` (or any Azure Storage SDK) should not be modified or
the blob/file may be unrecoverable.
* Keys for the AES256 block cipher are generated on a per-blob/file basis.
These keys are encrypted using RSAES-OAEP and encoded in the metadata.
* MD5 for both the pre-encrypted and encrypted version of the file is stored
in the entity metadata, if enabled. `skip_on` options will still work
transparently with encrypted blobs/files.
* MAC integrity checks are preferred over MD5 to validate encrypted data.
* Attempting to upload the same file that exists in Azure Storage, but the
file in Azure Storage is not encrypted will not occur if any `skip_on` match
condition succeeds. This behavior can be overridden by deleting the target
file in Azure Storage or disabling the `skip_on` behavior.
* Attempting to upload the same file as an encrypted blob with a different
RSA key will not occur if the file content MD5 is the same. This behavior
can be overridden by deleting the target file in Azure Storage or disabling
the `skip_on` `md5_match` behavior.
* Zero-byte files are not encrypted.
