OWN_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
UC_DIRNAME := fuzzware-unicorn

LIBDIR = $(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/
INC=-I$(OWN_DIR)/../../../unicorn/$(UC_DIRNAME)/include
BIN_EXT = .so

CC = cc
CFLAGS += -fpic $(INC) -g -O3 #-Wall
LDFLAGS += -shared -L$(LIBDIR) -lunicorn

.PHONY: all clean

SOURCES = native_hooks.c timer.c native_tracing.c interrupt_triggers.c state_snapshotting.c mmio.c stream.c arch.c uc_snapshot.c  fuzz.c fuzzware_mmio_model.c
SOURCES += arm/cortexm_nvic.c arm/cortexm_systick.c arm/util.c
SOURCES += sparc/interrupt_controller.c sparc/systick.c

SOURCES += fuzzer/fuzzer.c

BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

native_hooks.so: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

all: native_hooks.so

clean:
	rm -rf *.o arm/*.o sparc/*.o fuzzer/*.o $(BINS)
