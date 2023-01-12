# variables
CC = gcc -Wall

PROJECT_DIR=.
SRC_DIR=./src
BIN_DIR=./bin
DIST_DIR=./dist

# CI/CD
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

docker-up:
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

$(BIN_DIR)/Gateway.o: $(BIN_DIR) $(SRC_DIR)/Gateway.c $(SRC_DIR)/api.h
	$(CC) -o "$(BIN_DIR)/Gateway.o" -c "$(SRC_DIR)/Gateway.c"

# applications
Sniffer: $(DIST_DIR) $(BIN_DIR)/Sniffer.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Sniffer" "$(BIN_DIR)/Sniffer.o" "$(BIN_DIR)/api.o"

Spoofer: $(DIST_DIR) $(BIN_DIR)/Spoofer.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Spoofer" "$(BIN_DIR)/Spoofer.o" "$(BIN_DIR)/api.o"

Gateway: $(DIST_DIR) $(BIN_DIR)/Gateway.o $(BIN_DIR)/api.o
	$(CC) -o "$(DIST_DIR)/Gateway" "$(BIN_DIR)/Gateway.o" "$(BIN_DIR)/api.o"


# build
build: Sniffer Spoofer Gateway

rebuild: clean build
