# Source file
SRC      := iolog.c

# AArch64 cross build settings
CROSS_CC     ?= aarch64-linux-gnu-gcc
CROSS_CFLAGS += -Wall -Wextra -O2 -fPIC
CROSS_LDFLAGS? = $(LDFLAGS)
CROSS_TARGET := libiolog-aarch64.so

DOCKER_NAME := iolog_builder


.PHONY: all aarch64 clean


all: aarch64

aarch64: $(CROSS_TARGET)

$(CROSS_TARGET): $(SRC)
	$(CROSS_CC) $(CROSS_CFLAGS) -shared -o $@ $< $(CROSS_LDFLAGS)

clean:
	rm -f $(TARGET) $(CROSS_TARGET)


docker-create:
	docker build -t $(DOCKER_NAME) .

docker-get:
	CONTAINER_ID=$$(docker create $(DOCKER_NAME)); \
	docker start $$CONTAINER_ID; \
	docker cp $$CONTAINER_ID:/build/$(CROSS_TARGET) ./$(CROSS_TARGET); \
	docker rm -f $$CONTAINER_ID

