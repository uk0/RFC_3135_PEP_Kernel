# RFC 3135 PEP TCP Accelerator Kernel Module
# Performance Enhancing Proxy - Split-TCP Implementation

MODULE_NAME := pep_accelerator

# 内核模块对象文件
obj-m += $(MODULE_NAME).o

# 多源文件组成模块
$(MODULE_NAME)-objs := src/pep_main.o \
                       src/pep_flow.o \
                       src/pep_engine.o \
                       src/pep_netfilter.o \
                       src/pep_mempool.o \
                       src/pep_congestion.o \
                       src/pep_shaper.o \
                       src/pep_checksum.o \
                       src/pep_spoofing.o \
                       src/pep_retrans.o \
                       src/pep_byte_cache.o \
                       src/pep_proc.o \
                       src/pep_learning.o \
                       src/pep_region.o \
                       src/pep_scheduler.o \
                       src/pep_rtt_probe.o \
                       src/pep_fec.o \
                       src/pep_pmtu.o \
                       src/pep_gso.o

# 编译标志
ccflags-y := -I$(src)/include -DDEBUG -O2

# 内核构建目录
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# 默认目标
all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers modules.order

install: modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

load:
	insmod $(MODULE_NAME).ko

unload:
	rmmod $(MODULE_NAME)

reload: unload load

# 调试目标
debug:
	$(MAKE) -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-DPEP_DEBUG -g"

.PHONY: all modules clean install load unload reload debug
