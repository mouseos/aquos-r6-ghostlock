#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define NREG 33
#define RMASK ((UINT64_C(1) << NREG) - 1)

static uint64_t get64(const uint8_t *ring, uint64_t size, uint64_t pos) {
  uint64_t v, off = pos & (size - 1);
  if (off + 8 <= size) memcpy(&v, ring + off, 8);
  else {
    uint8_t b[8]; uint64_t first = size - off;
    memcpy(b, ring + off, first); memcpy(b + first, ring, 8 - first);
    memcpy(&v, b, 8);
  }
  return v;
}

static void nop_handler(int sig) { (void)sig; }

int main(int argc, char **argv) {
  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s runtime_text_hex [signal|enforce]\n", argv[0]); return 2;
  }
  uint64_t text = strtoull(argv[1], NULL, 16);
  int signal_mode = argc == 3 && strcmp(argv[2], "signal") == 0;
  int enforce_mode = argc == 3 && strcmp(argv[2], "enforce") == 0;
  if (signal_mode) signal(SIGUSR1, nop_handler);
  struct perf_event_attr a = {0};
  a.type = PERF_TYPE_SOFTWARE; a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK; a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = RMASK; a.sample_max_stack = 16;
  a.disabled = 1; a.exclude_user = 1; a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) { perror("perf_event_open"); return 1; }
  long ps = sysconf(_SC_PAGESIZE); size_t map_size = (size_t)ps * 257;
  struct perf_event_mmap_page *m = mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { perror("mmap"); return 1; }
  volatile int a1 = 1, a2 = 0;
  int enforce_fd = enforce_mode ? open("/sys/fs/selinux/enforce", O_RDONLY) : -1;
  char enforce_buf[8];
  ioctl(fd, PERF_EVENT_IOC_RESET, 0); ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 300000; i++) {
    if (signal_mode)
      (void)syscall(__NR_tgkill, getpid(), syscall(__NR_gettid), SIGUSR1);
    else if (enforce_mode) {
      (void)syscall(__NR_lseek, enforce_fd, 0, SEEK_SET);
      (void)syscall(__NR_read, enforce_fd, enforce_buf, sizeof(enforce_buf));
    }
    else
      (void)syscall(__NR_futex, &a1,
                    FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                    0, NULL, &a2, 0);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0); __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  unsigned shown = 0, samples = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h; uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = get64(ring, size, pos); pos += 16;
      uint64_t nr = get64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = get64(ring, size, pos); pos += 8; samples++;
      uint64_t low = text + (signal_mode ? 0x210000 :
                             enforce_mode ? 0x680000 : 0x300000);
      uint64_t high = text + (signal_mode ? 0x230000 :
                              enforce_mode ? 0x6a0000 : 0x330000);
      if (shown < 120 && abi && ip >= low && ip < high &&
          pos + NREG * 8 <= tail + h.size) {
        printf("ip=%016" PRIx64 " off=%08" PRIx64 " sp=%016" PRIx64,
               ip, ip - text, get64(ring, size, pos + 31 * 8));
        for (unsigned reg = 0; reg < 11; reg++)
          printf(" x%u=%016" PRIx64, reg, get64(ring, size, pos + reg * 8));
        putchar('\n'); shown++;
      }
    }
    tail += h.size;
  }
  printf("samples=%u shown=%u last_errno=%d\n", samples, shown, errno);
  return shown ? 0 : 3;
}
