ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-alpine AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /src

RUN python -m venv /opt/validator

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN /opt/validator/bin/pip install . \
    && /opt/validator/bin/pip uninstall --yes pip


FROM python:${PYTHON_VERSION}-alpine AS runtime

RUN addgroup -S validator \
    && adduser -S -G validator -h /home/validator validator \
    && mkdir /work \
    && chown validator:validator /work

COPY --from=builder /opt/validator /opt/validator

ENV PATH="/opt/validator/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /work
USER validator

ENTRYPOINT ["registry-validator"]
