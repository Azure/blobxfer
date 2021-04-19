# Change Log

## [Unreleased]

## [1.10.0] - 2021-04-19
### Changed
- Updated dependencies
- Loosen some dependency requirements
([#121](https://github.com/Azure/blobxfer/issues/121))
- `synccopy` no longer copies storage objects at the same level and name as
a virtual directory when specified with `--strip-components`
([#117](https://github.com/Azure/blobxfer/issues/117))
- Binary builds and Docker images are now built against Python 3.9.4
- MacOS X binary built against 10.15

### Fixed
- Fix multiple argument CLI options (`--include`/`--exclude`)
([#126](https://github.com/Azure/blobxfer/issues/126))

### Removed
- Python < 3.6 support dropped

## [1.9.4] - 2019-11-13
### Changed
- Updated dependencies
- Binary builds are now built against Python 3.7.5
- Windows Docker image uses Python 3.7.5

### Fixed
- Fix issues with `--storage-url` and `--sync-copy-dest-storage-url` for
Synccopy operations ([#108](https://github.com/Azure/blobxfer/issues/108))
- Fix overwrite optimization and skip-on regression
([#109](https://github.com/Azure/blobxfer/issues/109))

## [1.9.3] - 2019-09-19
### Fixed
- Fix SAS permission derivation on SAS keys with leading '?' character

## [1.9.2] - 2019-09-09
### Fixed
- Fix default overwrite behavior on upload performing point query lookups
for each remote object

## [1.9.1] - 2019-08-19
### Fixed
- Multi-process concurrency workers (MD5 and decryption) on Python 3.7+
([#104](https://github.com/Azure/blobxfer/issues/104))

### Removed
- Python 2.7 support on Windows dropped

## [1.9.0] - 2019-07-22
### Added
- Support a `--delete-only` option which allows operations to proceed while
no transfer takes place but deletions do occur (in conjunction with
`--delete`) ([#101](https://github.com/Azure/blobxfer/issues/101)). This
option can be used for all operation types.
- Support the `--strip-components` option for `synccopy` operations
([#103](https://github.com/Azure/blobxfer/issues/103))

### Changed
- Updated dependencies
- Binary builds are now built against Python 3.7.4
- Windows Docker image uses Python 3.7.4
- Linux Docker builds are based on Alpine 3.10

### Fixed
- Regression in YAML config and `synccopy` operations
([#100](https://github.com/Azure/blobxfer/issues/100))
- Allow synccopy source from Azure Files with a storage account key

## [1.8.0] - 2019-05-30
### Added
- Server side copy support for `synccopy` commands. By default, `synccopy`
operations will now use server side copies eliminating the machine initiating
the operation as a potential bottleneck. Arbitrary URLs are now supported
in the `--remote-path` argument that reference a single object
([#93](https://github.com/Azure/blobxfer/issues/93)).
- Support setting the Content Type property explicitly
([#95](https://github.com/Azure/blobxfer/issues/95)). Specifying this
option will override automatically inferring the MIME type of the file.

### Changed
- **Breaking Change**: Docker images going forward are now hosted in
Microsoft Container Registry
- Updated dependencies
- Binary builds are now built against Python 3.7.3
- Windows Docker image uses Python 3.7.3

### Fixed
- Allow `--rename` in `synccopy` operations
- Fix retries for certain SSL errors
([#98](https://github.com/Azure/blobxfer/issues/98))

### Removed
- Python 3.4 support dropped

## [1.7.1] - 2019-03-04
### Changed
- Updated dependencies

### Fixed
- Directories created with [blobfuse](https://github.com/Azure/azure-storage-fuse)
would conflict with files nested under these directories due to zero-byte
blobs acting as virtual directory placeholders
([#92](https://github.com/Azure/blobxfer/issues/92)). These blobs are
now skipped for download operations.

## [1.7.0] - 2019-02-26
### Added
- Support ability to set the Cache Control property
([#91](https://github.com/Azure/blobxfer/issues/91))

### Changed
- Updated dependencies
- Linux Docker image based on Alpine 3.9

### Fixed
- Invalid key with vectorized IO and single object concurrency control

## [1.6.0] - 2019-01-14
### Added
- Configurable max single object concurrency control for downloads via
`--max-single-object-concurrency`

### Changed
- Updated dependencies
- Binary builds are now built against Python 3.7.2
- Windows Docker image uses Python 3.7.2

### Fixed
- Premature download termination under single object concurrency control
([#89](https://github.com/Azure/blobxfer/issues/89))

## [1.5.5] - 2018-11-19
### Changed
- Updated dependencies

### Fixed
- More coverage for Windows retries

## [1.5.4] - 2018-11-05
### Changed
- Version ranges added in dependencies
- Updated dependencies

### Fixed
- Fix spacing in console/log output in Windows

## [1.5.3] - 2018-10-26
### Changed
- Binary builds are now built against Python 3.7.1
- Windows Docker image uses Python 3.7.1
- Timeouts were modified along with retries on 429
- Updated dependencies

### Fixed
- Fix SAS permission scope derivation on file shares
([#88](https://github.com/Azure/blobxfer/issues/88))
- Fix Python 3.7 compatibility issues

## [1.5.0] - 2018-09-17
### Added
- Mac OS binary build

### Changed
- CI/CD pipeline changed to Azure DevOps (VSTS)
- Windows binaries are now signed

### Fixed
- Fix CLI settings retrieval
- Fix `--delete` on Windows ([#84](https://github.com/Azure/blobxfer/issues/84))
- Scope `--delete` on remote path ([#85](https://github.com/Azure/blobxfer/issues/85))
- Fix various SAS permission regressions from the previous release

## [1.4.0] - 2018-08-08
### Added
- Azure Storage URL support for the CLI via `--storage-url` and
`--sync-copy-dest-storage-url` ([#79](https://github.com/Azure/blobxfer/issues/79)).
Please see the usage docs for more information.
- `--restore-file-lmt` option for download operations
([#82](https://github.com/Azure/blobxfer/issues/82)). Please see the usage
docs for more information.

### Changed
- **Breaking Change**: `restore_file_attributes` boolean property under
`download` has been replaced with `restore_file_properties` map containing
`attributes` and `lmt` for YAML configurations. This change was done to
provide consistency with the `store_file_properties` map under `upload`.
Please see the YAML configuration doc for more information.
- Updated dependencies

### Fixed
- Fix and improve SAS handling to limit functionality based on SAS token
scope and permissions ([#80](https://github.com/Azure/blobxfer/issues/80)).
Please see the usage and limitations docs for more information.

## [1.3.1] - 2018-06-29
### Changed
- Updated dependencies
- Update Windows Docker image to use Python 3.6.6

### Fixed
- Always use generic string check fallback for retry ([#77](https://github.com/Azure/blobxfer/issues/77))

## [1.3.0] - 2018-06-15
### Added
- Support for `--dry-run` parameter for all operations. A dry run will
log intent of an action and is a way to test the potential outcome of
an operation. ([#74](https://github.com/Azure/blobxfer/issues/74))
- `--connect-timeout` and `--read-timeout` options providing fine grained
timeout control. The `--timeout` option is now deprecated.

### Changed
- Updated dependencies

### Fixed
- Further improve retry handling ([#75](https://github.com/Azure/blobxfer/issues/75))

## [1.2.1] - 2018-05-23
### Changed
- Updated dependencies

### Fixed
- Skip on options not properly respected with delete option for synccopy
and upload (#72)
- Improve retry handling code

## [1.2.0] - 2018-04-19
### Added
- Support for `--strip-components` parameter on download (#69)
- Support for `-q`/`--quiet` option to suppress output to stdout (#70)

### Changed
- Update dependencies to latest
- Update Windows Docker image to use Python 3.6.5

### Fixed
- Non-MD5 upload invalid ref (#60)
- Retry of broken encrypted upload (#61)
- Detect non-Base64 encoded storage account keys (#62)
- Regression in download of zero-length blobs (#68)

## [1.1.1] - 2018-01-30
### Changed
- Updated Azure Storage dependencies to 1.0.0 (GA version)

### Fixed
- `--sync-copy-dest-mode` option not honored from CLI (#57)

## [1.1.0] - 2018-01-18
### Added
- Support for setting blob access tiers on Upload and SyncCopy

### Changed
- Default chunk size and thread counts for downloading
- Limit number of concurrent downloads per object
- Update dependencies to latest
- Update Docker images to Alpine 3.7 and Python 3.6.4

### Fixed
- Connection pool thread exhaustion

## [1.0.0] - 2017-11-06
### Added
- Sample YAML config

### Changed
- Default max retries is now set to 1000 per request
- Updated dependencies to latest

### Fixed
- Retry handler does not retry on name resolution failures (#46)

## [1.0.0rc3] - 2017-10-27
### Added
- Fileshare snapshot source support for download and synccopy (#53)
- HTTP Proxy support
- `max_retries` option

### Changed
- Pre-built binaries are now built with Python 3.6

### Fixed
- Errant exceptions thrown for `--skip-on-filesize-match` and
`--skip-on-lmt-ge` options (#51)
- Match `dest_mode` to `mode` when `dest_mode` is set to `auto` on synccopy

## [1.0.0rc2] - 2017-10-16
### Added
- `--enable-azure-storage-logger` option to enable the Azure Storage
logger (#47)

### Changed
- Migrate to codecov.io for coverage reports

### Fixed
- Basic `--endpoint` check (#46)
- Fix CLI options not being correctly fed to config (#48)

## [1.0.0rc1] - 2017-10-05
### Added
- Expanded `blobxfer.api` to eliminate other imports
- Data movement library usage guide
- `--show-config` option added which decouples configuration output from
the `-v` verbose option

### Changed
- `version` property for YAML configuration is now required
- `--rename` is automatically enabled for when `stdin` is the source
- `--include` and `--exclude` filters are now checked for invalid rglob specs
- Update dependencies to latest

### Fixed
- Multiple `--include` and/or `--exclude` from the commandline
- `--file-md5` option being ignored on download
- Incorrect MD5 computation for unaligned page blobs on upload

## [1.0.0b2] - 2017-09-01
### Added
- `upload` from `stdin` to page blob support. Optional
`--stdin-as-page-blob-size` parameter added. Please see current limitations
doc for more information.
- `upload` from `stdin` `--rename` support
- `synccopy` single object `--rename` support

### Changed
- AppVeyor integration
- Automated PyPI releases generated for tags
- Automated PyInstaller-based releases uploaded to GitHub for Windows and Linux
- Automated Windows Docker image build

### Fixed
- YAML config merge with CLI options when YAML options not present
- `synccopy` invocation without YAML config
- Test failures on Windows

## [1.0.0b1] - 2017-08-28
### Added
- Cross-mode synchronous copy support
- Duplicate detection (different local source paths mapping to the same
destination) on upload

### Changed
- Python 3.3 is no longer supported (due to `cryptography` dropping support
for 3.3).
- `--strip-components` now defaults to `0`
- `timeout_sec` YAML property is now named `timeout` and is a complex property
comprised of `connect` and `read` values expressed in seconds
- Test coverage improved
- Dependencies updated to latest

### Fixed
- Properly merge CLI options with YAML config options. You can now override
most YAML config settings with CLI options at runtime.
- Issue with zero-byte uploads
- Check for max page blob size

## [1.0.0a5] - 2017-06-09
### Added
- Synchronous copy support with the `synccopy` command. This command supports
multi-destination replication.

### Fixed
- Various YAML config file and CLI interaction issues
- Upload resume support with replication

## [1.0.0a4] - 2017-06-02
### Changed
- From scratch rewrite providing a consistent CLI experience and a vast
array of new and advanced features. Please see the
[1.0.0 Milestone](https://github.com/Azure/blobxfer/milestone/1) for a
catalog of changes.
- **Breaking Changes:** there have been a significant number of breaking
changes with the rewrite from the command-line invocation of `blobxfer`
itself to the options and environment variable names. Please review the
usage documentation carefully when upgrading from 0.12.1.
- All dependencies updated to latest

### Removed
- Azure Service Management certificate support

### Security
- Update cryptography requirement to 1.9

## [0.12.1] - 2016-12-09
### Changed
- Update all dependencies to latest versions

### Fixed
- Allow page blobs up to 1TB

### Security
- Update cryptography requirement to 1.6

## [0.12.0] - 2016-10-17
### Added
- Support for Account-level SAS keys
- Update README regarding non-normalized exceptions being thrown (#5)

## [0.11.5] - 2016-10-03
### Changed
- Update all dependencies to latest versions

### Fixed
- Fix incorrect fileshare path splitting (#3)

### Security
- Update cryptography requirement to 1.5.2

## [0.11.4] - 2016-09-12
### Added
- Created [Docker image](https://hub.docker.com/r/alfpark/blobxfer)

### Changed
- Update all dependencies to latest versions

### Fixed
- Fix `--delete` and blob listing with azure-storage (#1)

### Security
- Update cryptography requirement to 1.5

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
### Changed
- Pin azure dependencies due to breaking changes

### Fixed
- Minor bug fixes

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

[Unreleased]: https://github.com/Azure/blobxfer/compare/1.10.0...HEAD
[1.10.0]: https://github.com/Azure/blobxfer/compare/1.9.4...1.10.0
[1.9.4]: https://github.com/Azure/blobxfer/compare/1.9.3...1.9.4
[1.9.3]: https://github.com/Azure/blobxfer/compare/1.9.2...1.9.3
[1.9.2]: https://github.com/Azure/blobxfer/compare/1.9.1...1.9.2
[1.9.1]: https://github.com/Azure/blobxfer/compare/1.9.0...1.9.1
[1.9.0]: https://github.com/Azure/blobxfer/compare/1.8.0...1.9.0
[1.8.0]: https://github.com/Azure/blobxfer/compare/1.7.1...1.8.0
[1.7.1]: https://github.com/Azure/blobxfer/compare/1.7.0...1.7.1
[1.7.0]: https://github.com/Azure/blobxfer/compare/1.6.0...1.7.0
[1.6.0]: https://github.com/Azure/blobxfer/compare/1.5.5...1.6.0
[1.5.5]: https://github.com/Azure/blobxfer/compare/1.5.4...1.5.5
[1.5.4]: https://github.com/Azure/blobxfer/compare/1.5.3...1.5.4
[1.5.3]: https://github.com/Azure/blobxfer/compare/1.5.0...1.5.3
[1.5.0]: https://github.com/Azure/blobxfer/compare/1.4.0...1.5.0
[1.4.0]: https://github.com/Azure/blobxfer/compare/1.3.1...1.4.0
[1.3.1]: https://github.com/Azure/blobxfer/compare/1.3.0...1.3.1
[1.3.0]: https://github.com/Azure/blobxfer/compare/1.2.1...1.3.0
[1.2.1]: https://github.com/Azure/blobxfer/compare/1.2.0...1.2.1
[1.2.0]: https://github.com/Azure/blobxfer/compare/1.1.0...1.2.0
[1.1.1]: https://github.com/Azure/blobxfer/compare/1.1.0...1.1.1
[1.1.0]: https://github.com/Azure/blobxfer/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/Azure/blobxfer/compare/1.0.0rc3...1.0.0
[1.0.0rc3]: https://github.com/Azure/blobxfer/compare/1.0.0rc2...1.0.0rc3
[1.0.0rc2]: https://github.com/Azure/blobxfer/compare/1.0.0rc1...1.0.0rc2
[1.0.0rc1]: https://github.com/Azure/blobxfer/compare/1.0.0b2...1.0.0rc1
[1.0.0b2]: https://github.com/Azure/blobxfer/compare/1.0.0b1...1.0.0b2
[1.0.0b1]: https://github.com/Azure/blobxfer/compare/1.0.0a5...1.0.0b1
[1.0.0a5]: https://github.com/Azure/blobxfer/compare/1.0.0a4...1.0.0a5
[1.0.0a4]: https://github.com/Azure/blobxfer/compare/0.12.1...1.0.0a4
[0.12.1]: https://github.com/Azure/blobxfer/compare/0.12.0...0.12.1
[0.12.0]: https://github.com/Azure/blobxfer/compare/0.11.5...0.12.0
[0.11.5]: https://github.com/Azure/blobxfer/compare/0.11.4...0.11.5
[0.11.4]: https://github.com/Azure/blobxfer/compare/0.11.2...0.11.4
[0.11.2]: https://github.com/Azure/blobxfer/compare/e5e435a...0.11.2
