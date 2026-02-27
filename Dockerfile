FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN adduser --disabled-password --gecos "" --uid 10001 formalcloud

COPY pyproject.toml README.md /app/
COPY formal_cloud /app/formal_cloud

RUN pip install --no-cache-dir .

USER formalcloud

ENTRYPOINT ["formal-cloud"]
CMD ["--help"]
