FROM python:3.11-slim

WORKDIR /app

# System deps (optional but safe)
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . /app

CMD ["python", "ingest_knowledge_base.py"]