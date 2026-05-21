FROM python:3.12-slim

# Python optimizations
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install only system deps (keep minimal)
RUN apt-get update && apt-get install -y gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (best caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code separately
COPY src/ ./src
COPY agent/ ./agent

# Move working dir to src (important for imports like main:app)
WORKDIR /app/src

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]