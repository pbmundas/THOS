FROM python:3.11-slim

WORKDIR /repo

COPY services/knowledge/requirements.txt /repo/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

COPY services /repo/services

CMD ["python", "-m", "services.knowledge.ingest_knowledge_base"]
