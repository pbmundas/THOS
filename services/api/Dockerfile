FROM python:3.11-slim

WORKDIR /repo

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /repo/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

# Copy the whole repo so `services.*` absolute imports resolve correctly
COPY services /repo/services

ENV PYTHONPATH=/repo
ENV PYTHONUNBUFFERED=1

EXPOSE 8100

CMD ["python", "-m", "services.api.server"]
