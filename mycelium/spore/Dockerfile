FROM python:3.11-slim

LABEL maintainer="Project Mycelium"
LABEL description="Spore Node – IoT Decoy Container"

RUN apt-get update && apt-get install -y --no-install-recommends \
    libmodbus-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose all emulated ports
EXPOSE 1883 502 8080

CMD ["python", "spore_main.py"]
