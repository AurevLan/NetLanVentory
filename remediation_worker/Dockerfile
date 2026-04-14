# Remediation worker — runs ansible-playbook --check and --diff in an
# isolated container, then posts results back to the NetLanVentory API.
#
# Security:
#   - non-root user
#   - no DB access (talks to the API only)
#   - SSH keys mounted read-only from a Docker secret
#   - sudoers whitelist enforced by the target SSH account, not by this container

FROM python:3.12-slim

# System deps for ansible
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        sshpass \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd --create-home --shell /bin/bash --uid 10001 worker

WORKDIR /app

COPY remediation_worker/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY remediation_worker/worker.py ./worker.py

USER worker

ENV PYTHONUNBUFFERED=1 \
    NLV_API_URL=http://app:8000/api/v1 \
    POLL_INTERVAL_SECONDS=10

CMD ["python", "/app/worker.py"]
