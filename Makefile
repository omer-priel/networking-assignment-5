# variables
CC = gcc -Wall

NET_DEV=wlp0s20f3

PROJECT_DIR=.
SRC_DIR=./src
BIN_DIR=./bin
DIST_DIR=./dist

# CI/CD
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-rebuild:
	docker-compose build
	docker-compose up -d

# units
$(BIN_DIR):
	mkdir $(BIN_DIR)

$(DIST_DIR):
	mkdir $(DIST_DIR)

$(BIN_DIR)/api.o: $(BIN_DIR) $(SRC_DIR)/api.c $(SRC_DIR)/config.h
	$(CC) -o "$(BIN_DIR)/api.o" -c "$(SRC_DIR)/api.c"

$(BIN_DIR)/Sniffer.o: $(BIN_DIR) $(SRC_DIR)/Sniffer.c $(SRC_DIR)/api.h
	$(CC) -o "$(BIN_DIR)/Sniffer.o" -c "$(SRC_DIR)/Sniffer.c"

$(BIN_DIR)/Spoofer.o: $(BIN_DIR) $(SRC_DIR)/Spoofer.c $(SRC_DIR)/api.h
	$(CC) -o "$(BIN_DIR)/Spoofer.o" -c "$(SRC_DIR)/Spoofer.c"

$(BIN_DIR)/SnifferSpoofer.o: $(BIN_DIR) $(SRC_DIR)/SnifferSpoofer.c $(SRC_DIR)/api.h
	$(CC) -o "$(BIN_DIR)/SnifferSpoofer.o" -c "$(SRC_DIR)/SnifferSpoofer.c"

$(BIN_DIR)/Gateway.o: $(BIN_DIR) $(SRC_DIR)/Gateway.c $(SRC_DIR)/api.h
	$(CC) -o "$(BIN_DIR)/Gateway.o" -c "$(SRC_DIR)/Gateway.c"

# applications
Sniffer: $(DIST_DIR) $(BIN_DIR)/Sniffer.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Sniffer" "$(BIN_DIR)/Sniffer.o" "$(BIN_DIR)/api.o" -lpcap

Spoofer: $(DIST_DIR) $(BIN_DIR)/Spoofer.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Spoofer" "$(BIN_DIR)/Spoofer.o" "$(BIN_DIR)/api.o"

SnifferSpoofer: $(DIST_DIR) $(BIN_DIR)/SnifferSpoofer.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/SnifferSpoofer" "$(BIN_DIR)/SnifferSpoofer.o" "$(BIN_DIR)/api.o" -lpcap

Gateway: $(DIST_DIR) $(BIN_DIR)/Gateway.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Gateway" "$(BIN_DIR)/Gateway.o" "$(BIN_DIR)/api.o" -lpcap


# build
build: Sniffer Spoofer SnifferSpoofer Gateway

# actions
test-sniffer-open:
	docker-compose exec attacker ./Sniffer $(NET_DEV)

test-sniffer-curl:
	docker-compose exec attacker curl google.com

test-sniffer-curl-2:
	docker-compose exec attacker curl www.columbia.edu/~fdc/sample.html

test-sniffer-show:
	docker-compose exec attacker cat ./Sniffer.txt

test-sniffer-clean:
	docker-compose exec attacker rm -f ./Sniffer.txt

test-spoofer-1:
	docker-compose exec attacker ./Spoofer 10.9.0.6 10.9.0.7

test-spoofer-2:
	docker-compose exec attacker ./Spoofer 8.8.8.8 10.9.0.7

test-attacker-open:
	docker-compose exec attacker ./SnifferSpoofer $(NET_DEV)

test-attacker-host-A-to-A:
	docker-compose exec hostA ping 10.9.0.6 -c 4

test-attacker-host-A-to-B:
	docker-compose exec hostA ping 10.9.0.7 -c 4

test-attacker-host-A-to-google:
	docker-compose exec hostA ping 8.8.8.8 -c 4

test-attacker-host-A-to-not-found:
	docker-compose exec hostA ping 8.8.200.200 -c 4

test-gateway-open:
	docker-compose exec attacker ./Gateway 8000

test-gateway-send-host-A:
	docker-compose exec hostA bash -c "echo -n Gateway-from-Host-A | nc -4u -w1 10.9.0.1 8000"

test-gateway-send-host-B:
	docker-compose exec hostB bash -c "echo -n Gateway-from-Host-B | nc -4u -w1 10.9.0.1 8000"

test-gateway-send-host-C:
	docker-compose exec hostC bash -c "echo -n Gateway-from-Host-C | nc -4u -w1 10.9.0.1 8000"

test-gateway-sending:
	docker-compose exec hostA bash -c "echo -n Gateway-from-Host-A-1 | nc -4u -w1 10.9.0.1 8000"
	docker-compose exec hostB bash -c "echo -n Gateway-from-Host-B-1 | nc -4u -w1 10.9.0.1 8000"
	docker-compose exec hostC bash -c "echo -n Gateway-from-Host-C-1 | nc -4u -w1 10.9.0.1 8000"
	docker-compose exec hostA bash -c "echo -n Gateway-from-Host-A-2 | nc -4u -w1 10.9.0.1 8000"
	docker-compose exec hostB bash -c "echo -n Gateway-from-Host-B-2 | nc -4u -w1 10.9.0.1 8000"
	docker-compose exec hostC bash -c "echo -n Gateway-from-Host-C-2 | nc -4u -w1 10.9.0.1 8000"