FROM python:3.11-slim

WORKDIR /repo

COPY requirements.txt /repo/requirements.txt
COPY requirements-forensics.txt /repo/requirements-forensics.txt

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        binutils \
        clamav \
        clamav-freshclam \
        curl \
        ewf-tools \
        file \
        g++ \
        libimage-exiftool-perl \
        regripper \
        sqlite3 \
        sleuthkit \
        tshark \
    && pip install --prefer-binary --no-cache-dir \
        -r requirements.txt \
        -r requirements-forensics.txt \
    && apt-get purge -y --auto-remove g++ \
    && rm -rf /var/lib/apt/lists/*

# The Python capa package intentionally ships without the default community
# rules. Pin those rules to an immutable revision so scans remain reproducible.
ARG CAPA_RULES_REF=67f626eecb123e74c3e0cb464f3feaf8c0345cb2
RUN mkdir -p /opt/capa-rules \
    && curl -fsSL "https://github.com/mandiant/capa-rules/archive/${CAPA_RULES_REF}.tar.gz" \
       | tar -xz --strip-components=1 -C /opt/capa-rules

# Copy the whole repo so `services.*` absolute imports resolve correctly
COPY services /repo/services

ENV PYTHONPATH=/repo
ENV PYTHONUNBUFFERED=1
ENV FORENSIC_CAPA_RULES_DIR=/opt/capa-rules
ENV PATH="/opt/forensic-tools:${PATH}"

EXPOSE 8200

# main.py only defines `app = FastAPI(...)` — it never calls uvicorn.run()
# itself, so it must be launched via the uvicorn CLI, not `python main.py`.
CMD ["sh", "-c", "python -m services.detection.verify_sigmahq_rules && exec uvicorn services.orchestration.main:app --host 0.0.0.0 --port 8200"]
