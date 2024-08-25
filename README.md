# ProxDNS

**ProxDNS** is a Python-based DNS service that dynamically resolves VM domains to their IP addresses using the Proxmox Virtual Environment (PVE) API.  
The service periodically queries the Proxmox API to retrieve running VMs' IPs and serves DNS requests accordingly.

## Features

- Automatically resolves domain names for Proxmox VMs using their IPv4 and IPv6 addresses.
- Supports DNS A and AAAA records.
- Exposes an HTTP API for listing active VM domains and their IP addresses.
- Periodically refreshes DNS records based on the current state of Proxmox.

## Local

Make sure you have the necessary Python dependencies installed:

```bash
pip install -r requirements.txt
```

To run the service locally, you can use the following command:

```bash
USER=proxmoxdns@pve PASSWORD=secretpass HOST=proxmox.local LOGGING=true SUBDOMAINS=true python server.py
```

## Docker

A pre-built Docker image is available for easy deployment.

### Docker Setup

To deploy ProxDNS with Docker, use the following `docker-compose.yml` configuration:

```yaml
services:
  proxdns:
    image: vvzvlad/dns_proxy:latest
    container_name: proxdns
    ports:
      - "53:53/tcp"
      - "53:53/udp"
      - "8076:80/tcp"
    environment:
      - HOST=proxmox.local
      - USER=proxmoxdns@pve
      - PASSWORD=secretpass
      - LOGGING=true
      - SUBDOMAINS=true
    restart: unless-stopped
    labels:
      com.centurylinklabs.watchtower.enable: true
    logging:
      driver: "json-file"
      options:
        max-file: 5
        max-size: 10m
```

### Environment Variables Description

This section explains the purpose of each environment variable used in the ProxDNS service configuration:

- **HOST**: The address of the Proxmox server 
- **USER**: The username used to access the Proxmox API. This user must have the necessary privileges to monitor and audit VMs.
- **PASSWORD**: The password for the specified user to connect to the Proxmox API.
- **LOGGING**: Set the logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).
- **SUBDOMAINS**: If set with any value (not necessarily `true`), all subdomains of a VM will resolve to the same IP address as the main domain. For example, `sub.domain.com` will resolve to the same IP as `domain.com`.

## Proxmox Setup

You need to configure a user with the necessary permissions on Proxmox to allow the service to fetch VM information. 

1. Create a user in Proxmox:

```bash
pveum user add proxmoxdns@pve --password secretpass
```

1. Add a role for the user:

```bash
pveum role add ProxmoxDNS --privs "VM.Audit,VM.Monitor"
```

1. Assign the role to the user:

```bash
pveum aclmod /vms --user proxmoxdns@pve --role ProxmoxDNS
```

## Periodic DNS Updates

ProxDNS automatically updates the DNS records by querying the Proxmox API periodically.  
The interval between updates is dynamically adjusted based on changes in the number of VMs.

## Logging

To configure logging, set the `LOGGING` environment variable to the desired logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL).  
This will control the verbosity of log information about DNS queries, API calls, and other service activities.
