# Top-level build. `make` builds everything; `sudo make test` runs a quick check.
CLANG   ?= clang
# Ubuntu's /usr/sbin/bpftool is a wrapper that breaks if linux-tools for the exact
# kernel is missing, so prefer the real binary.
BPFTOOL ?= $(shell ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | tail -1 || command -v bpftool)
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
BUILD   := build

CFLAGS  := -O2 -g -Wall -Wextra -Wno-unused-parameter -Iinclude -Isrc -I$(BUILD)
LDLIBS  := -lbpf -lelf -lz

# Part 3/4 drop their .c files into consumer/ and they get built automatically
CONSUMER_SRC := $(wildcard consumer/*.c)

# Part 2: every workloads/X.c becomes build/X (standalone, no eBPF)
WORKLOAD_BIN := $(patsubst workloads/%.c,$(BUILD)/%,$(wildcard workloads/*.c))

TARGETS := $(BUILD)/evdump $(BUILD)/libedr.a $(WORKLOAD_BIN)
ifneq ($(CONSUMER_SRC),)
TARGETS += $(BUILD)/edr_consumer
endif

all: $(TARGETS)

.DELETE_ON_ERROR:

$(BUILD):
	mkdir -p $@

# kernel type definitions, generated from the RUNNING kernel
$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/probes.bpf.o: bpf/probes.bpf.c include/event.h $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -target bpf -mcpu=v3 -D__TARGET_ARCH_$(ARCH) \
		-Iinclude -I$(BUILD) -c $< -o $@

$(BUILD)/probes.skel.h: $(BUILD)/probes.bpf.o
	$(BPFTOOL) gen skeleton $< name probes_bpf > $@

$(BUILD)/backend.o: src/backend.c src/backend.h include/event.h $(BUILD)/probes.skel.h
	$(CC) $(CFLAGS) -c $< -o $@

# the library every user-space component links against
$(BUILD)/libedr.a: $(BUILD)/backend.o
	$(AR) rcs $@ $^

$(BUILD)/evdump: tools/evdump.c $(BUILD)/libedr.a
	$(CC) $(CFLAGS) $< $(BUILD)/libedr.a $(LDLIBS) -o $@

$(BUILD)/edr_consumer: $(CONSUMER_SRC) $(wildcard consumer/*.h) $(BUILD)/libedr.a
	$(CC) $(CFLAGS) -Iconsumer $(CONSUMER_SRC) $(BUILD)/libedr.a $(LDLIBS) -lm -o $@

$(WORKLOAD_BIN): $(BUILD)/%: workloads/%.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -o $@ $<

# quick smoke test of all three designs (needs root)
test: all
	@for d in fifo percpu prio; do ./$(BUILD)/evdump --design $$d --duration 3 --no-read || exit 1; done

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
