#define _GNU_SOURCE
#include <inttypes.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#define REGS 33
#define REGMASK ((UINT64_C(1) << REGS) - 1)

static uint64_t qword(const uint8_t *p, uint64_t size, uint64_t pos) {
  uint64_t v, off = pos & (size - 1);
  if (off + 8 <= size) memcpy(&v, p + off, 8);
  else { uint8_t b[8]; uint64_t n=size-off; memcpy(b,p+off,n);
    memcpy(b+n,p,8-n); memcpy(&v,b,8); }
  return v;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  uint64_t addr = strtoull(argv[1], NULL, 0);
  struct perf_event_attr a;
  memset(&a, 0, sizeof(a));
  a.type = PERF_TYPE_BREAKPOINT; a.size = sizeof(a);
  a.bp_type = HW_BREAKPOINT_X; a.bp_addr = addr; a.bp_len = 4;
  a.sample_period = 1;
  a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_REGS_INTR;
  a.sample_regs_intr = REGMASK; a.disabled = 1; a.exclude_hv = 1;
  int fd = syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
  if (fd < 0) { perror("perf_event_open"); return 3; }
  long ps=sysconf(_SC_PAGESIZE); size_t ms=(size_t)ps*9;
  struct perf_event_mmap_page *m=mmap(NULL,ms,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
  if (m==MAP_FAILED) { perror("mmap"); return 4; }
  ioctl(fd,PERF_EVENT_IOC_RESET,0); ioctl(fd,PERF_EVENT_IOC_ENABLE,0);
  for(int i=0;i<10000;i++) syscall(__NR_getuid);
  ioctl(fd,PERF_EVENT_IOC_DISABLE,0); __sync_synchronize();
  uint8_t *ring=(uint8_t*)m+m->data_offset; uint64_t size=m->data_size;
  uint64_t tail=m->data_tail,head=m->data_head; unsigned count=0;
  while(tail+sizeof(struct perf_event_header)<=head) {
    struct perf_event_header h; uint64_t off=tail&(size-1);
    if(off+sizeof(h)<=size) memcpy(&h,ring+off,sizeof(h)); else { tail+=8; continue; }
    if(h.size<sizeof(h)||tail+h.size>head) break;
    if(h.type==PERF_RECORD_SAMPLE) {
      uint64_t pos=tail+sizeof(h),ip=qword(ring,size,pos); pos+=16;
      uint64_t abi=qword(ring,size,pos); pos+=8;
      if(abi && pos+REGS*8<=tail+h.size) {
        printf("ip=%016" PRIx64 " x8=%016" PRIx64 "\n",ip,qword(ring,size,pos+64));
        count++;
      }
    }
    tail+=h.size;
  }
  printf("samples=%u head=%" PRIu64 "\n",count,head);
  return count?0:5;
}
