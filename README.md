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
will be the one that does the actions with Sniffer, Spoofer and the Gateway (under dist folder) \
\
For testing the Tasks (A, B, C, and D): \
First, change the NET_DEV variable in the Makefile to the primary network device of your computer, Use this command two see it \

```bash
ifconfig
```

The primary network device will be the last one on the list \
For example, my network device name is wlp0s20f3

### Task A (TCP)

In this task, we created a sniffer that sniffs TCP packets and saves them in a file called Sniffer.txt \
You can see it yourself by:
Open two terminals, In the first run the following commands:

```bash
make test-sniffer-open
```

And in the second one run the following commands:

```bash
test-sniffer-curl
test-sniffer-curl-2
test-sniffer-show
```

### Task B (ICMP)

In this task, we created a spoofer that takes the destination (IPv4) and fake address (IPv4). And send a ping to the destination on behalf of the fake address \
You can see it yourself by run the following commands:

```bash
test-spoofer-1
test-spoofer-2
```

### Task C (ICMP)

In this task, we created an attacker that sniffs ICMP pings and sends a reply on behalf of the destination to the sender \
You can see it yourself by:
Open two terminals, In the first run the following commands:

```bash
test-attacker-open
```

And in the second one run the following commands:

```bash
test-attacker-host-A-to-B
test-attacker-host-A-to-google
test-attacker-host-A-to-not-found
```

It will not sniffer the fist ping beacuse host A to host B is in docker network and the sniffer dos sinff only from NET_DEV

### Task D (UDP)

In this task, we created a "gateway" that gets pocket with UDP on port 8000 and replies to 0.5 from them in the port 8001 \
You can see it yourself by:
Open two terminals, In the first run the following commands:

```bash
test-gateway-open
```

And in the second one run the following commands:

```bash
test-gateway-sending
```

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
