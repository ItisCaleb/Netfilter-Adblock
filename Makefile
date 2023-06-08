SRC_DIR = ./src
SRC = $(wildcard $(SRC_DIR)/*.c)

all:
	./generate_hash.sh $(SRC_DIR)
	gcc -o adblock $(SRC) -lnetfilter_queue
