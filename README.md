
```
services:
  proxdns:
    image: vvzvlad/dns_proxy:latest
    container_name: proxdns
    ports:
      - "53:5354/tcp"
      - "53:5354/udp"
    environment:
      - HOST=proxmox.lc 
      - USER=proxmoxdns@pve
      - PASSWORD=passofproxmoxdns
    restart: unless-stopped
    labels:
      com.centurylinklabs.watchtower.enable: true
    logging:
      driver: "json-file"
      options:
        max-file: 5
        max-size: 10m
```
