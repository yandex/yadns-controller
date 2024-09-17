BINARY = yadns-xdp

CC = clang
DEBUG_FLAGS = -D_LOG_DEBUG -DQPARSE2

# -DDEBUG

# -DEDNS - parsing and response with EDNS option to indicate
#  payload size of 512?

# -DQPARSE2 - alternative (less complicated) function to parse
#  qname, be default we use QPARSE1

# also please check vmlinux.h itself
VMLINIX_VERSION = 515

SANDBOX_VMLINUX_H_6_02 = 5060812881
SANDBOX_VMLINUX_H_5_15 = 5035456922
SANDBOX_VMLINUX_H_5_19 = 5060816200

# libbpf src could be used as contrib in 
# arc repo, or as native repo from github [1]
# [1] https://github.com/libbpf/libbpf
#LIBBPF = /var/tmp/libbpf/src

A = ../
LIBBPF = $(A)/libbpf/src

TARGET = $(BINARY).bpf.o
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# -mcpu=v3 for some reason this bpf is not working with cpu=v3
COMMON_CLDFLAGS = -fcolor-diagnostics -D_FILE_OFFSET_BITS=64 -Wall -Winvalid-pch -g -fPIC -g -O2

# indicating header files should fix bpf subdirectory search problem
EBPF_CLDFLAGS = $(COMMON_CLDFLAGS) -D__KERNEL__ -D__TARGET_ARCH_x86 --target=bpf -Wno-macro-redefined -D__BPF_TRACING__ -D__x86_64__ -DCORE -isystem $(LIBBPF)

app: $(TARGET)
.PHONY: app

libbpf_github:
	rm -rf /var/tmp/libbpf
	git clone https://github.com/libbpf/libbpf /var/tmp/libbpf

$(TARGET): $(BINARY).bpf.c $(BINARY).bpf.h vmlinux.h vmlinux_$(VMLINIX_VERSION).h
	$(CC) $(LINUX_H) $(EBPF_CLDFLAGS) $(DEBUG_FLAGS) -o $@ -c $<
	llvm-strip -g $@

vmlinux_515.h:
	ya download sbr:$(SANDBOX_VMLINUX_H_5_15) --output=vmlinux_515.h --overwrite
	chmod 644 vmlinux_515.h
vmlinux_519.h:
	ya download sbr:$(SANDBOX_VMLINUX_H_5_19) --output=vmlinux_519.h --overwrite
	chmod 644 vmlinux_519.h
vmlinux_602.h:
	ya download sbr:$(SANDBOX_VMLINUX_H_6_02) --output=vmlinux_602.h --overwrite
	chmod 644 vmlinux_602.h

vmlinux_XXX.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux_XXX.h

install:
	sudo ip link set dev eth0 xdp obj ./$(BINARY).bpf.o section xdp/xdp_dns
	sudo ip link set dev lo xdp obj ./$(BINARY).bpf.o section xdp/xdp_dns
deinstall:
	sudo ip link set eth0 xdpgeneric off
	sudo ip link set lo xdpgeneric off
	sudo rm -rf /sys/fs/bpf/xdp/globals/yadns_xdp_rr_a
	sudo rm -rf /sys/fs/bpf/xdp/globals/yadns_xdp_rr_aaaa

clean:
	- test -f $(TARGET) && rm $(TARGET) || true
