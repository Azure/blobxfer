# blobxfer Installation
There are multiple available options for installing `blobxfer`. If you
only require the CLI functionality, then you can install via one of
three methods:

* [Python package from PyPI](#pypi) (i.e., `pip install`)
* [Pre-built binary](#binary)
* [Docker image](#docker)

If you require the `blobxfer` data movement library, then you will
need to install the [Python package from PyPI](#pypi).

## <a name="pypi"></a>Python Package from PyPI
`blobxfer` is a pure Python package, however, some dependencies require a C
compiler and supporting libraries if there is no binary wheel for that
dependency and your platform. Please follow the pre-requisites section first
prior to invoking installation via `pip`.

It is strongly recommended to use a 64-bit Python interpreter.

### Pre-requisites
`blobxfer` has dependencies which require a C compiler if your platform does
not have pre-made binary wheels for these dependencies. Please follow the
instructions below for your platform. You will need to run the following
commands via `sudo` or as root.

#### Ubuntu
```shell
# for Python3 (recommended)
apt-get update
apt-get install -y build-essential libssl-dev libffi-dev python3-dev python3-pip

# for Python2
apt-get update
apt-get install -y build-essential libssl-dev libffi-dev python-dev python-pip
```

#### CentOS/RHEL
```shell
# for Python3 (recommended)
yum install -y epel-release
yum install -y python34 python34-devel gcc openssl-devel libffi-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python3

# for Python2
yum install -y gcc openssl-devel libffi-devel python-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python
```

#### SLES/OpenSUSE
```shell
# for Python3 (recommended)
zypper ref
zypper -n in gcc libopenssl-devel libffi48-devel python3-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python3

# for Python2
zypper ref
zypper -n in gcc libopenssl-devel libffi48-devel python-devel
curl -fSsL https://bootstrap.pypa.io/get-pip.py | python
```

#### Mac OS X
Python 2.7 should come pre-installed. However, if you want to install
`blobxfer` for Python 3.5+ (recommended), please follow the steps outlined on
[this guide](http://docs.python-guide.org/en/latest/starting/install3/osx/#install3-osx)
to ensure that you have the latest version of Python, a compiler and pip.

#### Windows
Please install at least Python 3.5 or later to avoid requiring a
compiler. If you must use Python 2.7, you can download the necessary
development headers and compiler [from Microsoft](http://aka.ms/vcpython27).
It is strongly recommended to use a 64-bit interpreter.

#### Windows Subsystem for Linux
Please follow the same instructions for the Linux distribution installed.

### Installation via `pip`
After the pre-requisite steps have been completed then install the
[blobxfer](https://pypi.python.org/pypi/blobxfer) Python package:

```shell
# for Python3
pip3 install blobxfer

# for Python2
pip install blobxfer
```

`blobxfer` is compatible with Python 2.7 and 3.5+. To install for Python 3
(which is recommended), some distributions may use `pip3` instead of `pip`.
Installing into a virtual environment or your user area via `--user`
is recommended to avoid installation issues and conflicts with system-wide
Python packages.

## <a name="binary"></a>Pre-built Binary
Download an appropriate [Release](https://github.com/Azure/blobxfer/releases)
binary for your operating system. Pre-built binaries are not available
for all platforms and architectures at this time.

Note that for the Linux pre-built binary, it may not work on all
distributions. If this is the case, please pick an alternate installation
method. After downloading the binary, make sure that the executable bit is
set via `chmod +x` prior to attempting to execute the file.

## <a name="docker"></a>Docker Image
[blobxfer](https://hub.docker.com/_/microsoft-blobxfer) is available on the
Microsoft Container Registry and can be retrieved with:

```shell
# Linux
docker pull mcr.microsoft.com/blobxfer

# Windows
docker pull mcr.microsoft.com/blobxfer:latest-windows
```

Please note that when invoking the Docker image, you will need to ensure
proper mapping of host to container mount points.
