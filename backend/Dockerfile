FROM python:3.11-slim

WORKDIR /app

ENV PYTHONPATH=/app

# ── System packages + security scanners ────────────────────────────────────
#   gcc, libpq-dev          → required to build Python packages
#   curl, unzip, git        → needed to download Nuclei & clone Nikto
#   nmap                    → port + service scanner
#   perl + libnet-ssleay    → required by Nikto (cloned below)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev curl unzip git ca-certificates \
        nmap \
        perl libnet-ssleay-perl libwhisker2-perl \
        libjson-perl libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

# ── Nikto — web server misconfig scanner (Perl script, install from GitHub)
# Nikto is not in Debian trixie main repo, so we clone the official source.
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && nikto -Version || true

# ── Nuclei (ProjectDiscovery) — fast template-based vuln scanner ───────────
# Pinned version for reproducibility. ~8000+ community templates auto-fetched
# on first run by Nuclei itself.
ARG NUCLEI_VERSION=3.2.9
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei \
    && /usr/local/bin/nuclei -version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
