FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

ENV PYTHONPATH=/app/src
EXPOSE 8082

CMD ["python", "-m", "soc_llm_triage.cli", "serve", "--host", "0.0.0.0", "--port", "8082"]
