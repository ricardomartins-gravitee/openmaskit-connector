FROM ghcr.io/astral-sh/uv:0.13.6@sha256:af22a52f5eafef3d78e551599d405c02df61919d18028f0cea8eda93bc9986d0 AS uv
FROM python:3.12.15-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4 AS build
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_PYTHON_DOWNLOADS=never UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE /build/
COPY src/ /build/src/
RUN uv sync --frozen --no-build --no-dev --no-editable --python /usr/local/bin/python
FROM python:3.12.15-alpine@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4
LABEL org.opencontainers.image.source="https://github.com/ricardomartins-gravitee/openmaskit-connector" org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /opt/venv /opt/venv
COPY LICENSE /usr/share/doc/openmaskit-connector/LICENSE
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
USER 10001:10001
EXPOSE 9495
ENTRYPOINT ["openmaskit-connector"]
