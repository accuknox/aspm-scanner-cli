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

RUN apk add --no-cache git

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
