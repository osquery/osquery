#pragma once

#ifndef __NR_perf_event_open
#if defined(__PPC__)
#define __NR_perf_event_open 319
#elif defined(__i386__)
#define __NR_perf_event_open 336
#elif defined(__x86_64__)
#define __NR_perf_event_open 298
#else
#error __NR_perf_event_open is undefined, probably this arch is not supported.
#endif
#endif

#ifndef __NR_bpf
#if defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#elif defined(__sparc__)
#define __NR_bpf 349
#elif defined(__s390__)
#define __NR_bpf 351
#else
#error __NR_bpf is undefined, probably this arch is not supported.
#endif
#endif
