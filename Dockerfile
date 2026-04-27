FROM python:3.11-slim

# Install nmap + whois for collectors
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap whois && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source code and config
COPY src/ src/
COPY config/ config/

# Create data directory
RUN mkdir -p data

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/stats')" || exit 1

ENTRYPOINT ["python", "-m", "surface_watch"]
CMD ["--scan-now"]
