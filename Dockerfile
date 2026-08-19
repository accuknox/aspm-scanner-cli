FROM docker:cli AS docker-cli

FROM python:3.10-alpine

ENV WORKDIR=/WORKDIR
WORKDIR $WORKDIR

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

# podman: daemonless container runtime for container-mode scans on
# containerd-only nodes (EKS/k3s) where no dockerd/docker.sock exists.
# docker CLI above stays for environments that do have a real daemon --
# aspm_cli.utils.container_runtime picks whichever is actually usable.
RUN apk add --no-cache git podman \
    && mkdir -p /etc/containers \
    && printf '{"default":[{"type":"insecureAcceptAnything"}]}\n' > /etc/containers/policy.json \
    && printf '[storage]\ndriver = "vfs"\n' > /etc/containers/storage.conf

COPY . /CODE

RUN pip install --upgrade \
      pip \
      wheel>=0.46.2 \
      setuptools>=70.0 \
      aiohttp>=3.13.3 \
      jaraco.context>=6.1.0

RUN pip install --no-cache-dir /CODE

RUN rm -rf /CODE

# Force secure version
RUN pip install --no-cache-dir --upgrade aiohttp>=3.13.3

ENTRYPOINT ["accuknox-aspm-scanner"]
