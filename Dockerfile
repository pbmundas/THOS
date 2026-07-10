FROM python:3.11-slim
 
# WORKDIR is "/" (not "/app") on purpose: the "app" directory copied in
# below IS the "app" Python package, so `from app.tools import ...`
# resolves correctly when PYTHONPATH includes "/".
WORKDIR /
 
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*
 
COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r /tmp/requirements.txt
 
COPY app /app
 
ENV PYTHONPATH=/
ENV PYTHONUNBUFFERED=1
 
EXPOSE 8100
 
CMD ["python", "-m", "app.server"]

FROM python:3.11-slim
 
# Same "app" package layout convention as the mcp-server image.
WORKDIR /
 
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*
 
COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r /tmp/requirements.txt
 
COPY app /app
 
ENV PYTHONPATH=/
ENV PYTHONUNBUFFERED=1
 
EXPOSE 8200
 
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8200"]

FROM python:3.11-slim
 
WORKDIR /app
 
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*
 
COPY requirements.txt /tmp/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r /tmp/requirements.txt
 
COPY app.py /app/app.py
 
ENV PYTHONUNBUFFERED=1
 
EXPOSE 7860
 
CMD ["python", "app.py"]
