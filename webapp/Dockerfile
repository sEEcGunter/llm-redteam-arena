FROM python:3.11-slim

WORKDIR /app

# curl needed for the healthcheck in docker-compose
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Dependencies layer — cached as long as requirements.txt doesn't change
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake the sentence-transformers model into the image so first startup is instant
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

COPY . .

# Persistent data lives here — mounted as a volume by docker-compose
RUN mkdir -p /app/data

EXPOSE 5000

CMD ["python", "app.py"]
