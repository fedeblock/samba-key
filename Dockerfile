FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends samba-common-bin smbclient && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY samba_key/ samba_key/
COPY gunicorn.conf.py gunicorn.conf.py
USER 65534:65534
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
# The access log is redacted by gunicorn.conf.py (no path, no query). See the
# "Keeping secrets out of logs" section of OPERATIONS.md.
CMD ["gunicorn", "--config", "gunicorn.conf.py", "--bind", "0.0.0.0:8080", "samba_key.app:app"]
