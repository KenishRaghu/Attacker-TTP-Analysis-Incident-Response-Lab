# Test and validation image for the IR / detection lab.
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    yara \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV PYTHONPATH=/app/src
CMD ["pytest", "-q"]
