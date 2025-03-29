FROM python:3.11-slim AS builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    git \
    curl \
    wget \
    nmap \
    libpq-dev \
    libmagic1 \
    libyaml-dev \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies in stages for better caching and reliability
COPY requirements.txt .

# Stage 1: Core dependencies
RUN pip install --upgrade pip && \
    pip install wheel setuptools && \
    pip install "numpy>=1.24.0" "pandas>=2.0.0" "scipy>=1.11.0" "requests>=2.31.0" "click>=8.1.0" "pyyaml>=6.0.0"

# Stage 2: Security and networking tools
RUN pip install "pycryptodome>=3.18.0" "python-nmap>=0.7.1" "scapy>=2.5.0" "pyOpenSSL>=23.2.0" "pyjwt>=2.8.0" && \
    pip install "python-magic>=0.4.27" "cryptography>=37.0.0" "paramiko>=3.3.0" "faker>=13.0.0" "pillow>=10.0.0"

# Stage 3: Web and utilities
RUN pip install "beautifulsoup4>=4.12.0" "aiohttp>=3.8.0" "fastapi>=0.103.0" "uvicorn>=0.23.0" "httpx>=0.25.0" && \
    pip install "tqdm>=4.66.0" "python-dotenv>=1.0.0"

# Stage 4: Data visualization
RUN pip install "matplotlib>=3.7.0" "seaborn>=0.12.0" "plotly>=5.15.0"

# Stage 5: Critical dependencies and basic ML
RUN apt-get update && apt-get install -y --no-install-recommends libffi-dev && \
    pip install cffi && \
    pip install joblib && \
    pip install "scikit-learn>=1.3.0" "nltk>=3.8.0"

# Stage 6: Advanced ML libraries - install with CPU-only option when possible
RUN pip install "gensim>=4.3.0" && \
    pip install "tensorflow-cpu>=2.12.0" && \
    pip install "torch>=2.0.0" --extra-index-url https://download.pytorch.org/whl/cpu && \
    pip install "transformers>=4.30.0" && \
    pip install "spacy>=3.6.0"

# Final stage: Install any remaining dependencies
RUN pip install -r requirements.txt

# Second stage for a smaller final image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONWARNINGS="ignore::DeprecationWarning,ignore::PendingDeprecationWarning" \
    CRYPTOGRAPHY_SUPPRESS_DEPRECATION_WARNINGS=1

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    wget \
    libpq-dev \
    libmagic1 \
    libyaml-dev \
    python3-yaml \
    man-db \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create non-root user for security
RUN groupadd -r phantomfuzzer && useradd -r -g phantomfuzzer phantomfuzzer

# Create necessary directories with proper permissions
RUN mkdir -p /app /data/wordlists /data/payloads /data/training /data/vulnerabilities /data/patterns
RUN chown -R phantomfuzzer:phantomfuzzer /app /data

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=phantomfuzzer:phantomfuzzer . /app/

# Copy and apply the Scapy patch to suppress cryptography warnings
COPY scapy_patch.py /tmp/scapy_patch.py
RUN python /tmp/scapy_patch.py

# Verify critical dependencies are installed
RUN echo "Verifying critical dependencies..." && \
    python -c "import yaml; print('PyYAML is properly installed')" && \
    python -c "import numpy; print('NumPy is properly installed')" && \
    python -c "import pandas; print('Pandas is properly installed')" && \
    python -c "import requests; print('Requests is properly installed')" && \
    python -c "import click; print('Click is properly installed')"

# Switch to non-root user
USER phantomfuzzer

# Expose port for API/Web interface
EXPOSE 8080

# Command to run the application
ENTRYPOINT ["python", "-m", "phantomfuzzer.cli"]
CMD ["--help"]
