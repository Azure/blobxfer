# Change Log

## [Unreleased]

## [0.11.2] - 2016-07-28
### Added
- Allow rsakeypassphrase to be passed as an environment variable

## 0.11.1 - 2016-07-05
### Added
- Allow storage account or sas key credentials to be passed as
  environment variables

## 0.11.0 - 2016-06-09
### Added
- Azure Files support, please refer to the General Notes section for
  limitations

### Changed
- `--blobep` option has been renamed to `--endpoint`

## 0.10.1 - 2016-06-06
### Changed
- Update all dependencies to latest versions
- Add flag for block/page level md5 computation which is now disabled by
  default

### Fixed
- Update against breaking changes from azure-storage 0.32.0

### Removed
- Remove RC designation from encryption/decryption functionality

### Security
- Update cryptography requirement to 1.4

## 0.10.0 - 2016-03-22
### Added
- Added ``--disable-urllib-warnings`` option to suppress urllib3 warnings
  (use with care)

### Changed
- Update script for compatibility with azure-storage 0.30.0 which
  is now a required dependency
- Promote encryption to RC status
- `--blobep` now refers to endpoint suffix rather than blob endpoint
  (e.g., core.windows.net rather than blob.core.windows.net)

### Security
- Update cryptography requirement to 1.3

## 0.9.9.11 - 2016-02-22
### Fixed
- Minor bug fixes

## Changed
- Pin azure dependencies due to breaking changes

### Security
- Update cryptography requirement to 1.2.2

## 0.9.9.10 - 2016-01-31
### Fixed
- Fix regression in blob name encoding with Python3

## 0.9.9.9 - 2016-01-29
### Added
- Emit warning when attempting to use remoteresource with a directory upload

### Changed
- Update setup.py dependencies to latest available versions

### Fixed
- Fix regression in single file upload and remoteresource renaming
- Replace socket exception handling with requests ConnectionError handling
- Properly handle blob names containing `?` if using SAS

## 0.9.9.8 - 2016-01-06
### Fixed
- Disable unnecessary thread daemonization
- Gracefully handle KeyboardInterrupts
- Explicitly add azure-common to setup.py install reqs

## 0.9.9.7 - 2016-01-05
### Added
- Add python environment and package info to parameter dump to aid issue/bug
  reports

### Changed
- Reduce number of default concurrent workers to 3x CPU count
- Change azure\_request backoff mechanism

### Fixed
- Make base requirements non-optional in import process
- Update azure\_request exception handling to support new Azure Storage Python
  SDK errors

## 0.9.9.6 - 2016-01-04
### Added
- Encryption support
- No file overwrite on download option
- Auto-detection of file mimetype
- Remote delete option
- Include pattern option

### Changed
- Replace keeprootdir with strip-components option
- Reduce the number of default concurrent workers to 4x CPU count

### Fixed
- Fix shared key upload with non-existent container
- Fix zero-byte blob download issue

## 0.9.9.5 - 2015-09-27
### Added
- File collation support

### Fixed
- Fix page alignment bug
- Reduce memory usage

## Old Releases
- 0.9.9.4: improve page blob upload algorithm to skip empty max size pages.
  fix zero length file uploads. fix single file upload that's skipped.
- 0.9.9.3: fix downloading of blobs with content length of zero
- 0.9.9.1: fix content length > 32bit for blob lists via SAS on Python2
- 0.9.9.0: update script for compatibility with new Azure Python packages
- 0.9.8: fix blob endpoint for non-SAS input, add retry on ServerBusy
- 0.9.7: normalize SAS keys (accept keys with or without ? char prefix)
- 0.9.6: revert local resource path expansion, PEP8 fixes
- 0.9.5: fix directory creation issue
- 0.9.4: fix Python3 compatibility issues
- 0.9.3: the script supports page blob uploading. To specify local files to
  upload as page blobs, specify the `--pageblob` parameter. The script also
  has a feature to detect files ending in the `.vhd` extension and will
  automatically upload just these files as page blobs while uploading other
  files as block blobs. Specify the `--autovhd` parameter (without the
  `--pageblob` parameter) to enable this behavior.
- 0.9.0: the script will automatically default to skipping files where if the
  MD5 checksum of either the local file or the stored MD5 of the remote
  resource respectively matches the remote resource or local file, then the
  upload or download for the file will be skipped. This capability will allow
  one to perform rsync-like operations where only files that have changed will
  be transferred. This behavior can be forcefully disabled by specifying
  `--no-skiponmatch`.
- 0.8.2: performance regression fixes

[Unreleased]: https://github.com/Azure/blobxfer/compare/v0.11.2...HEAD
[0.11.2]: https://github.com/Azure/blobxfer/compare/e5e435a...v0.11.2

