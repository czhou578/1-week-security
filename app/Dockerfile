FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install pip-audit

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip-audit -r requirements.txt || echo "⚠️ Vulnerabilities found in dependencies"

RUN pip install --no-cache-dir -r requirements.txt

RUN pip-audit

# Copy application code
COPY . .

# Expose port
EXPOSE 1337

# Run the application
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "1337", "--reload"]