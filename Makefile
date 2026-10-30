CC      = gcc
CFLAGS  = -Wall -Wextra -Wshadow -Wno-unused-function -O2 -g -Iinclude -MMD -MP
LDLIBS  = -lssl -lcrypto

SRC_DIR   = src
BUILD_DIR = build
TEST_DIR  = tests/unit

CORE_OBJS   = $(BUILD_DIR)/packet_utils.o \
              $(BUILD_DIR)/packet_crypto.o \
              $(BUILD_DIR)/packet_processor.o
DEVICE_OBJS = $(BUILD_DIR)/device.o $(BUILD_DIR)/handshake.o $(CORE_OBJS)

UNIT_SRCS = $(wildcard $(TEST_DIR)/*.c)
UNIT_BINS = $(UNIT_SRCS:$(TEST_DIR)/%.c=$(BUILD_DIR)/%)

all: $(BUILD_DIR)/device

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/device: $(DEVICE_OBJS)
	$(CC) $(DEVICE_OBJS) -o $@ $(LDLIBS) -lnetfilter_queue -lnfnetlink

# Unit tests need no root and no netfilter.
$(BUILD_DIR)/%: $(TEST_DIR)/%.c $(CORE_OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< $(CORE_OBJS) -o $@ $(LDLIBS)

test: $(UNIT_BINS)
	@for t in $(UNIT_BINS); do echo "== $$t"; $$t || exit 1; done
	@echo "ALL UNIT TESTS PASSED"

# End-to-end test through network namespaces (needs root).
e2e: all
	sudo ./scripts/e2e_test.sh

clean:
	rm -rf $(BUILD_DIR)

-include $(wildcard $(BUILD_DIR)/*.d)

.PHONY: all test e2e clean
