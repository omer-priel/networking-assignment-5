# networking-assignment-5

University assignment 5 for Networking

## Requirements

- Linux based Debian
- docker
- make

## Get Started

Run the following commands for the build the application:

```bash
make docker-build
make docker-up
```

4 container will created with IPs: 10.9.0.1 (attacker), 10.9.0.6, 10.9.0.7, 10.9.0.8 \
For the tasks use the dist fold. And the Host (not the containers) \
will be the one that dos the actions with Sniffer, Spoofer and the Gateway (under dist folder)

## Links

- <https://www.tcpdump.org/pcap.html>

## Other

- tcp
- icmp
- udp.dstport == 8000 || udp.srcport == 8000 || udp.srcport == 8001 || udp.dstport == 8001

## Authors

- Shlomit Ashkenazi
- Omer Priel

## License

MIT
