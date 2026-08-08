/*
 * Copyright (C) Hamish Coleman
 * SPDX-License-Identifier: GPL-3.0-only
 *
 */

#include <inttypes.h>
#include <n3n/benchmark.h>
#include <n3n/hexdump.h>  // for fhexdump
#include <signal.h>
#include <stdbool.h>            // for true, false
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "benchmark/staticdata.h"
#include "pktbuf.h"

#ifndef _WIN32
#include <sys/mman.h>           // for mmap, MAP_SHARED, MAP_ANONYMOUS
#include <sys/ptrace.h>         // for ptrace
#include <sys/types.h>          // for PTRACE_*
#include <sys/wait.h>           // for wait, WIFSTOPPED
#endif

#ifdef __linux__
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/user.h>           // for user_regs_struct
#include <sys/wait.h>           // for wait

#define LINUX_PERF  1
#endif

#if LINUX_PERF
static long perf_event_open (
    struct perf_event_attr *hw_event,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned long flags
) {
    int ret;
    ret = syscall(SYS_perf_event_open, hw_event, pid, cpu, group_fd, flags);
    return ret;
}

static int _perf_setup1 (struct bench_item *item, int id, uint64_t config) {
    struct perf_event_attr pe;

    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = config;
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    pe.sample_period = 0;
    pe.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;

    int fd = perf_event_open(&pe, 0, -1, item->fd[0], 0);
    if(fd == -1) {
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_ID, &item->id[id]);
    return fd;
}

static void perf_setup (struct bench_item *item) {
    item->fd[0] = -1;  // make the kernel see the first setup as leader
    item->fd[0] = _perf_setup1(item, 0,  PERF_COUNT_HW_INSTRUCTIONS);
    if(item->fd[0] == -1) {
        return;
    }

    item->fd[1] = _perf_setup1(item, 1, PERF_COUNT_HW_CPU_CYCLES);
    if(item->fd[1] == -1) {
        close(item->fd[0]);
        item->fd[0] = -1;
        return;
    }
}

static void perf_measure_start (struct bench_item *item) {
    if(item->fd[0] == -1) {
        return;
    }
    ioctl(item->fd[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(item->fd[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
}

struct read_format {
    uint64_t nr;
    struct {
        uint64_t value;
        uint64_t id;
    } values[2];
};

static void perf_measure_collect (struct bench_item *item) {
    if(item->fd[0] == -1) {
        return;
    }

    ioctl(item->fd[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

    struct read_format data;
    ssize_t count = read(item->fd[0], &data, sizeof(data));
    if(count == -1) {
        perror("read");
        exit(1);
    }

    for(int i = 0; i < data.nr; i++) {
        if(data.values[i].id == item->id[0]) {
            item->instr = data.values[i].value;
        } else if(data.values[i].id == item->id[1]) {
            item->cycles = data.values[i].value;
        } else {
            printf("Unexpected perf id\n");
            exit(1);
        }
    }

    close(item->fd[0]);
    close(item->fd[1]);
    item->fd[0] = -1;
    item->fd[1] = -1;
}
#else
static void perf_setup (struct bench_item *item) {
    return;
}
static void perf_measure_start (struct bench_item *item) {
    return;
}
static void perf_measure_collect (struct bench_item *item) {
    return;
}
#endif


static struct bench_item *registered_items = NULL;

void n3n_benchmark_register (struct bench_item *item) {
    item->next = registered_items;
    registered_items = item;
}

/* A do-nothing function to time the benchmark framework */
static const ssize_t bench_nop_run (
    void *ctx,
    const void *data_in,
    const ssize_t data_in_size,
    ssize_t *in
) {
    *in = 0;
    return 0;
}

static struct bench_item bench_nop = {
    .name = "NOP",
    .flags = BENCH_SKIP_CHECK,
    .ctx_size = 0,
    .run = bench_nop_run,
    .data_in = test_data_none,
    .data_out = test_data_none,
};

int generic_check (
    const struct bench_item *const p,
    const void *const got,
    const ssize_t got_size,
    const int level
) {
    if(got_size != n3n_pktbuf_getbufsize(&benchmark_test_data[p->data_out])) {
        // unexpected size results in an error
        return 1;
    }

    if(memcmp(
            n3n_pktbuf_getbufptr(&benchmark_test_data[p->data_out]),
            got,
            got_size
    ) != 0) {
        // not matching expected result is an error
        return 1;
    }

    return 0;
}

static void *item_setup (struct bench_item *item) {
    void *ctx;
    if(item->ctx_size) {
        ctx = malloc(item->ctx_size);
        if(!ctx) {
            fprintf(stderr, "Malloc failure");
            exit(1);
        }
    } else {
        ctx = NULL;
    }
    if(item->setup) {
        ctx = item->setup(ctx);
    }

    return ctx;
}

static void item_teardown (struct bench_item *item, void *ctx) {
    if(item->teardown) {
        item->teardown(ctx);
    }
    if(item->ctx_size) {
        free(ctx);
    }
}

static int item_fullname (struct bench_item *item, char *buf, ssize_t size, int level) {
    return snprintf(
        buf,
        size,
        "%s%s%s",
        item->name,
        (level || item->variant) ? ",":"",
        item->variant ? item->variant : ""
    );
}

#define ACTION_CHECK    1
#define ACTION_BENCH    2
#define ACTION_PTRACE   3

// Check if this item should be run or not
static bool item_allowrun (struct bench_item *item, int action, int filterc, char **filterv) {
    bool _default = false;

    // Calculate what the default action would be
    switch(action) {
        case ACTION_CHECK:
            if((item->flags & BENCH_SKIP_CHECK)) {
                _default = false;
            } else {
                _default = true;
            }
            break;

        case ACTION_BENCH:
            if(item->flags & BENCH_SKIP_BENCH) {
                _default = false;
            } else {
                _default = true;
            }
            break;

        case ACTION_PTRACE:
            if(item->flags & BENCH_SKIP_BENCH) {
                _default = false;
            } else if(item->flags & BENCH_SKIP_PTRACE) {
                _default = false;
            } else {
                _default = true;
            }
    }

    bool result = false;

    if(filterc > 0) {
        // Check all the filter strings
        for(int i = 0; i < filterc; i++) {
            if(!filterv[i]) {
                continue;
            }
            if(strcmp("ALL", filterv[i])==0) {
                result = true;
            }
            if(strcmp("DEFAULT", filterv[i])==0) {
                result = _default;
            }
            if(strcmp(item->name, filterv[i])==0) {
                result = true;
            }
        }
    } else {
        result = _default;
    }

    return result;
}

// These vars are shared between the harness and the traced pid when running a
// ptrace benchmark
struct pthread_shared {
    int loops;
    int sentinal;
};

static bool alarm_fired;

#ifndef _WIN32
static void handler (int nr) {
    alarm_fired = true;
}
#endif

#ifdef _WIN32
void benchmark_run_ptrace (const int seconds, int filterc, char **filterv) {
    fprintf(stderr,"no ptrace support on windows\n");
    return;
}

#elif defined(DARWIN)
void benchmark_run_ptrace (const int seconds, int filterc, char **filterv) {
    fprintf(stderr,"Macos only partially implements ptrace support\n");
    return;
}

#elif defined(__linux__)
static void run_one_item_ptrace (const int seconds, struct bench_item *item) {
    struct timeval tv1;
    struct timeval tv2;

    void *ctx = item_setup(item);
    const int input_size = n3n_pktbuf_getbufsize(
        &benchmark_test_data[item->data_in]
    );
    const void *input_data = n3n_pktbuf_getbufptr(
        &benchmark_test_data[item->data_in]
    );

    struct pthread_shared *shm = mmap(
        NULL,
        sizeof(struct pthread_shared),
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    if(!shm) {
        perror("mmap");
        exit(1);
    }

    shm->loops = 0;
    shm->sentinal = -1;

    struct sigaction sa = {
        .sa_handler = &handler,
    };
    sigaction(SIGALRM, &sa, NULL);

    gettimeofday(&tv1, NULL);

    pid_t pid = fork();

    if(pid == 0) {
        int wait_count = 10000;
        // Spin on ether the parent is ready or we get bored of waiting
        while(wait_count--) {
            if(shm->sentinal==0) {
                break;
            }
        }

        if(seconds > 0) {
            alarm_fired = false;
            alarm(seconds);
        } else {
            alarm_fired = true;
        }

        ssize_t count_in;
        shm->sentinal = 1;
        do {
            item->run(
                ctx,
                input_data,
                input_size,
                &count_in
            );
            shm->loops++;
        } while(!alarm_fired);
        shm->sentinal = 2;

        exit(0);
    } else {
        if(ptrace(PTRACE_ATTACH, pid, 0, 0)==-1) {
            perror("ptrace_attach");
            exit(1);
        }

        shm->sentinal = 0;
        int status;
        wait(&status);

        while(WIFSTOPPED(status)) {
            if(shm->sentinal == 1) {
                item->instr++;
#if 0
                // For debugging how accurate the measured cycle counts are,
                // output a trace of every instruction.
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, 0, &regs);

                uint64_t code = ptrace(PTRACE_PEEKTEXT, pid, regs.rip, 0);
                fhexdump(regs.rip, &code, 8, stdout);
#endif
            }

            int sig = WSTOPSIG(status);
            switch(sig) {
                case SIGALRM:
                    // Pass these through
                    break;
                case 0:
                case SIGTRAP:
                case SIGSTOP:
                    // Hide these from the child
                    sig = 0;
                    break;
                default:
                    printf("child got unexpected signal %i\n", sig);
#ifdef __x86_64__
                    struct user_regs_struct regs;
                    ptrace(PTRACE_GETREGS, pid, 0, &regs);
                    fhexdump(0, &regs, sizeof(regs), stdout);
                    printf("ip: 0x%08llx\n", regs.rip);
#endif
                    exit(1);
            }

            if(ptrace(PTRACE_SINGLESTEP, pid, 0, sig)==-1) {
                perror("ptrace_singlestep");
                exit(1);
            }
            wait(&status);
        }
    }

    gettimeofday(&tv2, NULL);

    item_teardown(item, ctx);

    timersub(&tv2, &tv1, &tv1);

    item->loops = shm->loops;
    item->sec = tv1.tv_sec;
    item->usec = tv1.tv_usec;
}

// Run all tests (or just those with the matching name) once and count how
// many instructions are
void benchmark_run_ptrace (const int seconds, int filterc, char **filterv) {
    struct bench_item *p;

    printf("name,variant,ptrace_seconds,ptrace_loops,ptrace_instr\n");

    for(p = registered_items; p; p = p->next) {
        if(!item_allowrun(p, ACTION_PTRACE, filterc, filterv)) {
            continue;
        }

        char name[40];
        item_fullname(p, &name[0], sizeof(name), 1);
        printf("%s,", name);
        fflush(stdout);

        run_one_item_ptrace(seconds, p);

        printf("%i.%06i,", p->sec, p->usec);
        printf("%" PRIu64 ",", p->loops);
        printf("%" PRIu64 "\n", p->instr);
    }
}

#else
void benchmark_run_ptrace (const int seconds, int filterc, char **filterv) {
    fprintf(stderr,"TODO: add ptrace based fakebench for this platform\n");
    return;
}
#endif

static void run_one_item (const int seconds, struct bench_item *item) {
    struct timeval tv1;
    struct timeval tv2;

    perf_setup(item);

    void *ctx = item_setup(item);
    const int input_size = n3n_pktbuf_getbufsize(
        &benchmark_test_data[item->data_in]
    );
    const void *input_data = n3n_pktbuf_getbufptr(
        &benchmark_test_data[item->data_in]
    );

    int loops = 0;
    alarm_fired = false;

#ifndef _WIN32
    struct sigaction sa = {
        .sa_handler = &handler,
    };
    sigaction(SIGALRM, &sa, NULL);

    if(seconds > 0) {
        alarm(seconds);
    } else {
        alarm_fired = true;
    }
#endif

    gettimeofday(&tv1, NULL);
    perf_measure_start(item);

    do {
        ssize_t count_in;

        ssize_t count_out = item->run(
            ctx,
            input_data,
            input_size,
            &count_in
        );
        loops++;
        item->bytes_in += count_in;
        item->bytes_out += count_out;

#ifdef _WIN32
        gettimeofday(&tv2, NULL);
        if((tv2.tv_sec - tv1.tv_sec) >= seconds) {
            alarm_fired = true;
        }
#endif
    } while(!alarm_fired);

    // TODO: per loop min/max/sumofsquares?

    perf_measure_collect(item);
    gettimeofday(&tv2, NULL);

    item_teardown(item, ctx);

#ifdef _WIN32
    // Just do a half-arsed job on windows, which matches their ability to
    // support POSIX
    tv1.tv_sec = tv2.tv_sec - tv1.tv_sec;
    tv1.tv_usec = tv2.tv_usec - tv1.tv_usec;
#else
    timersub(&tv2, &tv1, &tv1);
#endif

    item->loops = loops;
    item->sec = tv1.tv_sec;
    item->usec = tv1.tv_usec;
}

void benchmark_run_bench (const int level, const int seconds, int filterc, char **filterv) {
    struct bench_item *p;

    if(level==0) {
        printf("Each benchmark test runs for %i seconds\n\n", seconds);
    } else if(level==1) {
        printf("name,variant,seconds,bytes_in,bytes_out,loops,cycles,instr\n");
    }

    float seconds_total = 0;
    uint64_t cycles_total = 0;

    for(p = registered_items; p; p = p->next) {
        if(!item_allowrun(p, ACTION_BENCH, filterc, filterv)) {
            continue;
        }

        char name[40];
        item_fullname(p, &name[0], sizeof(name), level);

        if(level==0) {
            printf("%-20s", name);
        } else if(level==1) {
            printf("%s,", name);
        }
        fflush(stdout);

        run_one_item(seconds, p);

        if(level==0) {
            float seconds = ((float)p->usec / 1000000) + p->sec;
            seconds_total += seconds;

            printf(
                "%6.1fMB/s (%0.0f bytes) -> (%0.0f bytes)",
                (float)p->bytes_in / seconds / 1000000,
                (float)p->bytes_in / p->loops,
                (float)p->bytes_out / p->loops
            );

            if(p->cycles) {
                cycles_total += p->cycles;
                printf(
                    " cycles/loop=%0.0f ipc=%0.2f",
                    (float)p->cycles / p->loops,
                    (float)p->instr / p->cycles
                );
            }
            printf("\n");
        } else if(level==1) {
            printf("%i.%06i,", p->sec, p->usec);
            printf("%zd,%zd,", p->bytes_in, p->bytes_out);
            printf(
                "%" PRIu64 ",%" PRIu64 ",%" PRIu64 "\n",
                p->loops,
                p->cycles,
                p->instr
            );
        }
    }

    if(level==0) {
        printf("\n");
        printf("Bogo CPU speed %0.0fMhz\n", cycles_total/seconds_total/1000000);
    }
}

int benchmark_run_check (int level, int filterc, char **filterv) {
    int result = 0;

    for(struct bench_item *p = registered_items; p; p = p->next) {
        if(!item_allowrun(p, ACTION_CHECK, filterc, filterv)) {
            continue;
        }

        char name[40];
        item_fullname(p, &name[0], sizeof(name), level);
        fprintf(stderr, "%s: ", name);

        void *ctx = item_setup(p);
        const int input_size = n3n_pktbuf_getbufsize(
            &benchmark_test_data[p->data_in]
        );
        const void *input_data = n3n_pktbuf_getbufptr(
            &benchmark_test_data[p->data_in]
        );

        ssize_t count_in;

        ssize_t count_out = p->run(
            ctx,
            input_data,
            input_size,
            &count_in
        );

        fprintf(stderr, "tested\n");

        if(level) {
            printf("%s: data_in id=%i\n", p->name, p->data_in);
        }

        int this_result = 0;
        bool checked = false;

        if(p->check) {
            this_result += p->check(ctx, level);
            checked = true;
        }

        if(p->get_output) {
            const void *out_data = p->get_output(ctx);

            if(p->data_out != test_data_none) {
                this_result += generic_check(p, out_data, count_out, level);
                checked = true;
            }

            if(level) {
                printf("%s: data_out:\n", p->name);
                fhexdump(0, out_data, count_out, stdout);
            }
        }

        // Sanity check for bad data structures
        if(!checked) {
            fprintf(stderr, "WARNING: neither check nor get_output available\n");
            this_result += 1;
        }

        if(this_result) {
            fprintf(stderr, "%s: Unexpected result\n", p->name);
        }
        result += this_result;

        if(level) {
            printf("\n");
        }
        item_teardown(p, ctx);
    }

    return result;
}

void benchmark_list (const int level) {
    if(level==0) {
        // Pretty
        printf("\n");
        printf("/------ C = include in default check list\n");
        printf("|/----- B = include in default benchmark list\n");
        printf("||/---- F = include in default fakebench list\n");
        printf("||| Name                 ctx_size in out\n");
        printf("+++-====================-========-==-===\n");
    } else {
        // raw
        printf("flags,name,variant,size,data_in,data_out\n");
    }

    for(struct bench_item *p = registered_items; p; p = p->next) {
        char name[40];
        item_fullname(p, &name[0], sizeof(name), level);

        if(level==0) {
            // Pretty
            printf(
                "%s%s%s %-20s %8i %2i %3i\n",
                (p->flags & BENCH_SKIP_CHECK) ? "-":"C",
                (p->flags & BENCH_SKIP_BENCH) ? "-":"B",
                (p->flags & BENCH_SKIP_PTRACE) ? "-":"F",
                name,
                (int)p->ctx_size,
                p->data_in,
                p->data_out
            );
        } else {
            printf(
                "0x%02x,%s,%i,%i,%i\n",
                p->flags,
                name,
                (int)p->ctx_size,
                p->data_in,
                p->data_out
            );
        }
    }
}

void n3n_initfuncs_benchmark () {
    n3n_benchmark_register(&bench_nop);
}
