#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static int perf_open(struct perf_event_attr *attr) {
    return (int)syscall(__NR_perf_event_open, attr, 0, -1, -1, 0);
}

static int is_kernel_ip(uint64_t ip) {
    return ip >= UINT64_C(0xffff000000000000) &&
           ip <= UINT64_C(0xffffffffffff0000);
}

static uint64_t ring_u64(const uint8_t *ring, uint64_t ring_size,
                         uint64_t pos) {
    uint64_t value;
    uint64_t off = pos & (ring_size - 1);
    if (off + sizeof(value) <= ring_size) {
        memcpy(&value, ring + off, sizeof(value));
    } else {
        uint8_t bytes[sizeof(value)];
        uint64_t first = ring_size - off;
        memcpy(bytes, ring + off, first);
        memcpy(bytes + first, ring, sizeof(value) - first);
        memcpy(&value, bytes, sizeof(value));
    }
    return value;
}

int main(void) {
    long page_size = sysconf(_SC_PAGESIZE);
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_period = 100000;
    attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN;
    attr.sample_max_stack = 32;
    attr.disabled = 1;
    attr.exclude_hv = 1;

    int fd = perf_open(&attr);
    if (fd < 0) {
        fprintf(stderr, "perf_event_open: errno=%d (%s)\n", errno,
                strerror(errno));
        return 2;
    }

    size_t map_size = (size_t)page_size * 33;
    struct perf_event_mmap_page *meta = mmap(NULL, map_size,
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (meta == MAP_FAILED) {
        fprintf(stderr, "mmap: errno=%d (%s)\n", errno, strerror(errno));
        close(fd);
        return 3;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (int i = 0; i < 2000000; ++i)
        (void)syscall(__NR_gettid);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    __sync_synchronize();
    uint64_t head = meta->data_head;
    uint64_t tail = meta->data_tail;
    uint8_t *ring = (uint8_t *)meta + meta->data_offset;
    uint64_t ring_size = meta->data_size;
    uint64_t minimum = UINT64_MAX;
    uint64_t maximum = 0;
    unsigned found = 0;
    uint64_t examples[64];
    unsigned example_count = 0;

    while (tail + sizeof(struct perf_event_header) <= head) {
        struct perf_event_header hdr;
        uint64_t off = tail & (ring_size - 1);
        if (off + sizeof(hdr) <= ring_size) {
            memcpy(&hdr, ring + off, sizeof(hdr));
        } else {
            uint8_t bytes[sizeof(hdr)];
            size_t first = ring_size - off;
            memcpy(bytes, ring + off, first);
            memcpy(bytes + first, ring, sizeof(hdr) - first);
            memcpy(&hdr, bytes, sizeof(hdr));
        }
        if (hdr.size < sizeof(hdr) || tail + hdr.size > head)
            break;
        if (hdr.type == PERF_RECORD_SAMPLE) {
            uint64_t pos = tail + sizeof(hdr);
            uint64_t ip = ring_u64(ring, ring_size, pos);
            pos += 8 + 8; /* IP, then packed PID/TID. */
            uint64_t nr = ring_u64(ring, ring_size, pos);
            pos += 8;
            if (is_kernel_ip(ip)) {
                if (ip < minimum) minimum = ip;
                if (ip > maximum) maximum = ip;
                ++found;
                int seen = 0;
                for (unsigned j = 0; j < example_count; ++j)
                    seen |= examples[j] == ip;
                if (!seen && example_count < 64)
                    examples[example_count++] = ip;
            }
            for (uint64_t i = 0; i < nr && pos + 8 <= tail + hdr.size; ++i) {
                uint64_t candidate = ring_u64(ring, ring_size, pos);
                pos += 8;
                if (!is_kernel_ip(candidate))
                    continue;
                if (candidate < minimum) minimum = candidate;
                if (candidate > maximum) maximum = candidate;
                ++found;
                int seen = 0;
                for (unsigned j = 0; j < example_count; ++j)
                    seen |= examples[j] == candidate;
                if (!seen && example_count < 64)
                    examples[example_count++] = candidate;
            }
        }
        tail += hdr.size;
    }

    meta->data_tail = tail;
    printf("data_head=%" PRIu64 " kernel_ips=%u\n", head, found);
    if (found) {
        printf("min=%016" PRIx64 " max=%016" PRIx64
               " aligned_2m=%016" PRIx64 "\n",
               minimum, maximum, minimum & ~UINT64_C(0x1fffff));
        for (unsigned i = 0; i < example_count; ++i)
            printf("ip[%u]=%016" PRIx64 "\n", i, examples[i]);
    }
    munmap(meta, map_size);
    close(fd);
    return found ? 0 : 4;
}
