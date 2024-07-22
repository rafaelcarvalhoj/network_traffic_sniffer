FROM python:3.12

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    python3-pip \
    libpcap-dev \
    iproute2 && \
    pip install --no-cache-dir scapy

COPY . .

ENTRYPOINT ["python", "script.py"]
