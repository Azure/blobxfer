# blobxfer Installation
`blobxfer` is a pure Python package, however, some dependencies require a C
compiler and supporting libraries if there is no binary wheel. Please follow
the pre-requisites section first prior to invoking installation via `pip`.
Alternatively, you can use the
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

## Installation via `pip`
[blobxfer](https://pypi.python.org/pypi/blobxfer) is on PyPI and can be
installed via:

```shell
# for Python2
pip install blobxfer
# for Python3
pip3 instlal blobxfer
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
If you get an error that `azure.storage` cannot be found or loaded this means
that there was an issue installing this package with other `azure` packages
that share the same base namespace. You can correct this by issuing:
```shell
# for Python2
pip install azure-storage
# for Python3
pip3 install azure-storage
```
