#define _GNU_SOURCE

#include <inttypes.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define ARM64_REG_COUNT 33
#define ARM64_REG_MASK ((UINT64_C(1) << ARM64_REG_COUNT) - 1)

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

int main(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 10000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) { perror("perf_event_open"); return 1; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { perror("mmap"); return 1; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char status[4096];
  for (int i = 0; i < 100000; i++) {
    int status_fd = open("/proc/self/status", O_RDONLY);
    syscall(__NR_read, status_fd, status, sizeof(status));
    close(status_fd);
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  unsigned shown = 0, samples = 0;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = size - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = get64(ring, size, pos);
      pos += 16;
      uint64_t nr = get64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = get64(ring, size, pos); pos += 8;
      samples++;
      if (shown < 80 && abi != 0 && ip >= UINT64_C(0xffffffe25f7a417c) &&
          ip < UINT64_C(0xffffffe25f7a4564) &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        int any = 0;
        for (unsigned i = 0; i < ARM64_REG_COUNT; i++) {
          uint64_t v = get64(ring, size, pos + i * 8);
          if (v >= UINT64_C(0xffffff8000000000) &&
              v < UINT64_C(0xffffffffffff0000)) {
            if (!any) printf("sample ip=%016" PRIx64, ip);
            printf(" r%u=%016" PRIx64, i, v); any = 1;
          }
        }
        if (any) { putchar('\n'); shown++; }
      }
    }
    tail += h.size;
  }
  printf("samples=%u shown=%u head=%" PRIu64 "\n", samples, shown, head);
  return shown ? 0 : 2;
}
