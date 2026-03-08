FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends wireguard-tools && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .

RUN mkdir -p /var/run/wg-manager
CMD ["uvicorn", "main:app", "--uds", "/var/run/wg-manager/wg-manager.sock"]
