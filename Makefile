CC := aarch64-linux-gnu-gcc

SRCS := \
  src/core/main.c \
  src/core/util.c \
  src/core/slide.c \
  src/core/fops.c \
  src/core/pipe_physrw.c \
  src/core/root.c \
  src/core/miniadb.c \
  src/core/umh_root.c

CFLAGS := -O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
  -Wno-unused-function -Isrc/core -Isrc/devices \
  -DTARGET_CONFIG_H=\"aquos_r6/target.h\"
LDFLAGS := -static -pthread

.PHONY: all clean

all: build/ghostlock-r6 build/ghostlock54

build/ghostlock-r6: $(SRCS)
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm -f build/ghostlock-r6 build/ghostlock54

build/ghostlock54: src/ghostlock54.c
	mkdir -p build
	$(CC) -O2 -Wall -Wextra -Werror -static -pthread $< -o $@
