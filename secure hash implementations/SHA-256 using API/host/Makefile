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

# --- Original TEE Application ---
BINARY = secure_hash_host
SRCS = main.c
LDADD = -lteec -L$(OPTEE_CLIENT_EXPORT)/usr/lib

# --- New Baseline Application ---
BINARY_BASELINE = baseline_hasher
SRCS_BASELINE = main_baseline.c
LDADD_BASELINE = -lssl -lcrypto

# --- Build Rules ---
.PHONY: all
all: $(BINARY) $(BINARY_BASELINE)

$(BINARY): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $< $(LDADD)

$(BINARY_BASELINE): $(SRCS_BASELINE)
	$(CC) $(CFLAGS) -o $@ $< $(LDADD_BASELINE)

.PHONY: clean
clean:
	rm -f $(BINARY) $(BINARY_BASELINE)

.PHONY: install
install: all
	mkdir -p $(DESTDIR)/usr/bin
	cp $(BINARY) $(DESTDIR)/usr/bin/
	cp $(BINARY_BASELINE) $(DESTDIR)/usr/bin/
