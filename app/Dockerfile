FROM python:3.12-slim

# Pull in Debian security patches that the base image hasn't shipped yet;
# the release pipeline's CVE gate blocks on fixable OS CVEs otherwise.
RUN apt-get update \
    && apt-get -y upgrade \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Pinned in requirements.txt so Dependabot can propose updates.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
