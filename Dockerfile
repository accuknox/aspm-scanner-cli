FROM docker:cli AS docker-cli

FROM python:3.10-slim
ENV WORKDIR /WORKDIR
WORKDIR $WORKDIR
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PYTHONUNBUFFERED=1 \
    PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

COPY --from=docker-cli /usr/local/bin /usr/local/bin

RUN apt update -y && apt install curl git -y
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

COPY . /CODE
RUN  pip install  --no-cache-dir --no-cache /CODE
RUN rm -rf /CODE

ENTRYPOINT ["accuknox-aspm-scanner"]