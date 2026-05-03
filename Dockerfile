FROM ghcr.io/astral-sh/uv:python3.13-bookworm

RUN adduser --disabled-password agent
USER agent
WORKDIR /home/agent

COPY --chown=agent pyproject.toml uv.lock README.md ./
COPY --chown=agent src src

RUN uv sync --locked

ENTRYPOINT ["uv", "run", "src/server.py"]
CMD ["--host", "0.0.0.0", "--port", "9122"]
EXPOSE 9122
