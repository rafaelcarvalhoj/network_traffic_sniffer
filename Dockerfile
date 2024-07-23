FROM python:3.12

WORKDIR /app

RUN apt-get update && \
    apt-get install -y \
    python3-pip \
    libpcap-dev \
    iproute2

COPY . .

RUN pip install --no-cache-dir -r requiriments.txt

ENTRYPOINT ["python", "script.py"]
