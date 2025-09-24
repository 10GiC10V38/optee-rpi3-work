CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

# Adjust paths based on your OP-TEE build structure
OPTEE_CLIENT_EXPORT ?= $(CURDIR)/../optee_client/out/export

CFLAGS += -Wall -I$(OPTEE_CLIENT_EXPORT)/usr/include
LDADD += -lteec -L$(OPTEE_CLIENT_EXPORT)/usr/lib

BINARY = secure_hash_host

SRCS = main.c

.PHONY: all
all: $(BINARY)

$(BINARY): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(LDADD)

.PHONY: clean
clean:
	rm -f $(BINARY)

.PHONY: install
install: $(BINARY)
	mkdir -p $(DESTDIR)/usr/bin
	cp $(BINARY) $(DESTDIR)/usr/bin/
