

# Network Traffic Sniffer Script
This script captures network packets on a specified interface and provides traffic statistics.
You can also list available network interfaces without capturing packets.

# How to run?
Ensure you have Docker installed on your computer or Python >= 3.12.

## Docker version
Build the Docker Image:
```bash
docker build -t sniffer -f Dockerfile .
```
Run the Docker Container:
```bash
docker run <iterative_or_not> --net=host --privileged -v .:/app sniffer <args>
```
- If you want to run this script interactively, replace <iterative_or_not> with `-it`.
- If you want to run this script in detached mode, use `-d`.

## `<args>`
- **-h, --help** :Show this help message and exit
- **interface**: Network interface you want to sniff 
- **-si, --show-interfaces**: List all available network interfaces instead of capturing packets.
- **-gl, --gen-log**: Enable log generation for script output.

## Local version
The local version is only available to run in interactive mode. You need to press `Ctrl+C` to stop the sniffer.

### Usage:
Install the requiriments and create virtual enviroment:

```bash
sudo apt install python3-venv && \
    python3 -m venv .venv && \
    source .venv/bin/activate && \
    pip install -r requiriments.txt
```

Sniffer usage:
```bash
sudo .venv/bin/python3 script.py <args>
```

As with the Docker version, you need to pass the arguments to execute the script.

# Exemple Usage

## Docker Interactive Mode
To run the sniffer interactively with logging enabled on the `eth0` interface:
```bash
docker run -it --net=host --privileged -v .:/app sniffer eth0 -gl
```
Press `Ctrl+C` to stop the sniffer.

## Docker Detached Mode

To run the sniffer interactively with logging enabled on the `eth0` interface:
```bash
docker run -d --net=host --privileged -v .:/app sniffer eth0 -gl
```

### Stop sniffer in Docker Detached Mode

When running the network traffic sniffer script in Docker detached mode, the container runs in the background without interactive input. To stop this container, you can follow these steps:

### Step 1: List Running Containers

First, identify the running container by listing all active Docker containers. Open a terminal and execute:

```bash
docker ps
```

This command will display a list of running containers, along with their container IDs and names. Look for the container running the `sniffer` image.

### Step 2: Stop the Container

Once you have identified the container ID or name, you can stop the container using the following command:

```bash
docker stop <container_id_or_name>
```
Replace `<container_id_or_name>` with the actual container ID or name from the previous step. For example:

```bash
docker stop sniffer_container
```

or

```bash
docker stop 123abc456def
```

### Step 3: Verify the Container has Stopped

To ensure the container has stopped, you can list running containers again:

```bash
docker ps
```

The container should no longer be listed, indicating it has been stopped successfully.

### Optional: Remove the Container

If you want to remove the stopped container, you can do so with the following command:

```bash
docker rm <container_id_or_name>
```

For example:

```bash
docker rm sniffer_container` 
```

or

```bash
docker rm 123abc456def
```

Removing the container will free up system resources and prevent the container from being listed in future `docker ps -a` commands (which lists all containers, including stopped ones).
## Local Interactive Mode

Install the requiriments and create virtual enviroment:

```bash
sudo apt install python3-venv && \
    python3 -m venv .venv && \
    source .venv/bin/activate && \
    pip install -r requiriments.txt
```

To run the sniffer locally with logging enabled on the `eth0` interface:

```bash
sudo .venv/bin/python3 script.py eth0 -gl
```

To list all available network interfaces:

```bash
sudo .venv/bin/python3 script.py -si
```

# Logging in the File `sniffer.log` and `sniffer.csv`
The network traffic sniffer script includes a logging mechanism to capture and store information about sniffed network packets. This feature is especially useful for monitoring and analyzing network traffic over time. Here is an overview of how logging is implemented and how to use it effectively.
## Logging Configuration

The logging feature is controlled by the `--gen-log` argument when running the script. If this argument is provided, the script will generate log entries for each captured packet. The logs are saved in the file `sniffer.log`.

### Enabling Logging

To enable logging, use the `--gen-log` or `-gl` flag when executing the script:

# Data Analysis and Graph Generation
To generate data graphs from the logs, follow these steps:

1. Navigate to the Data Analysis Directory:

```bash
cd data_analysis_generator
```

2. Ensure the Python Environment is Activated and execute the script:

```bash
python3 gen_graphs.py
```

This script will process the log data and produce various graphs saved as image files in the same directory.

