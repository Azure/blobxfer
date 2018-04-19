# Dockerfile for Azure/blobxfer (Windows)
# Adapted from: https://github.com/StefanScherer/dockerfiles-windows/blob/master/python/Dockerfile

FROM python:3.6.5-windowsservercore-ltsc2016
MAINTAINER Fred Park <https://github.com/Azure/blobxfer>

ENV chocolateyUseWindowsCompression false
RUN iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')); \
    choco install --no-progress -y git -params "/GitAndUnixToolsOnPath"

ARG GIT_BRANCH
ARG GIT_COMMIT

WORKDIR C:\\blobxfer
RUN git clone -b $Env:GIT_BRANCH --single-branch --depth 5 https://github.com/Azure/blobxfer.git C:\blobxfer ; \
    git checkout $Env:GIT_COMMIT ; \
    pip install --no-cache-dir -e . ; \
    python setup.py install

RUN python -m compileall C:\Python\Lib ; \
    exit 0

FROM microsoft/nanoserver

COPY --from=0 /Python /Python
COPY --from=0 /blobxfer/THIRD_PARTY_NOTICES.txt /BLOBXFER_THIRD_PARTY_NOTICES.txt
COPY --from=0 /blobxfer/LICENSE /BLOBXFER_LICENSE.txt

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ENV PYTHON_VERSION 3.6.5
ENV PYTHON_PIP_VERSION 9.0.3

RUN $env:PATH = 'C:\Python;C:\Python\Scripts;{0}' -f $env:PATH ; \
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' -Name Path -Value $env:PATH ; \
    mkdir $env:APPDATA\Python\Python36\site-packages ; \
    Invoke-WebRequest 'https://bootstrap.pypa.io/get-pip.py' -OutFile 'get-pip.py' -UseBasicParsing ; \
    $replace = ('import tempfile{0}import site{0}site.getusersitepackages()' -f [char][int]10) ; \
    Get-Content get-pip.py | Foreach-Object { $_ -replace 'import tempfile', $replace } | Out-File -Encoding Ascii getpip.py ; \
    $pipInstall = ('pip=={0}' -f $env:PYTHON_PIP_VERSION) ; \
    python getpip.py $pipInstall ; \
    Remove-Item get-pip.py ; \
    Remove-Item getpip.py

ENTRYPOINT ["blobxfer"]
