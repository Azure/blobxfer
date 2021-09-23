# Dockerfile for Azure/blobxfer (Windows)

FROM python:3.9.7-windowsservercore-1809
MAINTAINER Fred Park <https://github.com/Azure/blobxfer>

ENV chocolateyUseWindowsCompression false
RUN [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 ; \
    iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')) ; \
    choco install --no-progress -y git -params "/GitAndUnixToolsOnPath"

ARG GIT_BRANCH
ARG GIT_COMMIT

WORKDIR C:\\blobxfer
RUN git clone -b $Env:GIT_BRANCH --single-branch --depth 5 https://github.com/Azure/blobxfer.git C:\blobxfer ; \
    git checkout $Env:GIT_COMMIT ; \
    pip install --no-cache-dir -e . ; \
    python setup.py install

RUN python -m compileall C:\Python\Lib\site-packages ; \
    exit 0

FROM mcr.microsoft.com/windows/nanoserver:1809

COPY --from=0 /Python /Python
COPY --from=0 /blobxfer/THIRD_PARTY_NOTICES.txt /BLOBXFER_THIRD_PARTY_NOTICES.txt
COPY --from=0 /blobxfer/LICENSE /BLOBXFER_LICENSE.txt

SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ENTRYPOINT ["blobxfer"]
