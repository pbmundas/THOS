FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --prefer-binary --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 8100

CMD ["python", "main.py"]