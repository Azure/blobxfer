# blobxfer Installation
`blobxfer` is a pure Python package, however, some dependencies require a C
compiler and supporting libraries if there is no binary wheel for that
dependency and your platform. Please follow the pre-requisites section first
prior to invoking installation via `pip`. Alternatively, you can use the
[blobxfer Docker image](https://hub.docker.com/r/alfpark/blobxfer/).

## Pre-requisites
`blobxfer` depends on `cryptography` and `ruamel.yaml` which require a
C compiler if your platform does not have a pre-made binary wheel. Please
follow the instructions below for your platform.

### Ubuntu
```shell
apt-get update
# for Python3 (recommended)
apt-get install -y build-essential libssl-dev libffi-dev python3-dev python3-pip
# for Python2
apt-get install -y build-essential libssl-dev libffi-dev python-dev python-pip
```

### CentOS/RHEL
```shell
# for Python2
yum install -y gcc openssl-dev libffi-devel python-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python
```

### SLES/OpenSUSE
```shell
zypper ref
# for Python2
zypper -n in gcc libopenssl-devel libffi48-devel python-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python
```

### Mac OS X
Python 2.7 should come pre-installed. However, if you want to install
`blobxfer` for Python 3.5+ (recommended), please follow the steps outlined on
[this guide](http://docs.python-guide.org/en/latest/starting/install/osx/)
to ensure that you have the latest version of Python, a compiler and pip.

### Windows
Please install at least Python 3.5 or higher to avoid requiring a
compiler. If you must use Python 2.7, you can download the necessary
development headers and compiler [from Microsoft](http://aka.ms/vcpython27).

## Installation via `pip`
[blobxfer](https://pypi.python.org/pypi/blobxfer) is on PyPI and can be
installed via:

```shell
# for Python3 (recommended)
pip3 install blobxfer
# for Python2
pip install blobxfer
```

`blobxfer` is compatible with Python 2.7 and 3.3+. To install for Python 3
(which is recommended), some distributions may use `pip3` instead of `pip`.
Installing into your user area via `--user` or via a virtual environment
is recommended to avoid installation issues with system-wide Python
packages.

## Installation via Docker
[blobxfer](https://hub.docker.com/r/alfpark/blobxfer/) is also on Docker
Hub and can be retrieved via:

```shell
docker pull alfpark/blobxfer
```

## Troubleshooting
#### `azure.storage` dependency not found
If you get an error such as `ImportError: No module named storage` or that
`azure.storage` cannot be found or loaded, then most likely there was a
conflict with this package with other `azure` packages that share the same
base namespace. You can correct this by issuing:
```shell
# for Python3
pip3 install --upgrade --force-reinstall azure-storage
# for Python2
pip install --upgrade --force-reinstall azure-storage
```
