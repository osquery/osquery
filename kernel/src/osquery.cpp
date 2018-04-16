/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <libkern/libkern.h>
#include <mach/mach_types.h>

#include <kern/debug.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/vnode.h>

// IOKit headers
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>

#include "publishers.h"

#include "circular_queue_kern.h"

#ifdef DEBUG
#define dbg_printf(...) printf("osquery kext: " __VA_ARGS__)
#else
#define dbg_printf(...) \
  do {                  \
  } while (0)
#endif

#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif

// Borrowed from VirtualBox
#if !defined(RT_GCC_SUPPORTS_VISIBILITY_HIDDEN) || \
    defined(RT_NO_VISIBILITY_HIDDEN)
#define DECLHIDDEN(type) type
#else
#define DECLHIDDEN(type) __attribute__((visibility("hidden"))) type
#endif

// Let the major number be decided for us.
#define OSQUERY_MAJOR -1
#define MAX_KMEM (20 * (1 << 20))
#define MIN_KMEM (8 * (1 << 10))

static struct {
  /// The shared (user/kernel space) circular queue holding event results.
  osquery_cqueue_t cqueue;

  /// The contiguous memory backing the circular queue.
  void *buffer;

  /// Configured size of the circular queue buffer.
  size_t buf_size;

  IOMemoryDescriptor *md;
  IOMemoryMap *mm;
  void *devfs;
  int major_number;
  int open_count;

  /// IOCTL API handling lock/mutex data.
  lck_grp_attr_t *lck_grp_attr;
  lck_grp_t *lck_grp;
  lck_attr_t *lck_attr;

  /// IOCTL API handling mutex.
  lck_mtx_t *mtx;
} osquery = {.open_count = 0,
             .buffer = NULL,
             .buf_size = 0,
             .md = NULL,
             .mm = NULL,
             .devfs = NULL,
             .major_number = OSQUERY_MAJOR};

static inline void setup_locks() {
  // Create locks. Cannot be done on the stack.
  osquery.lck_grp_attr = lck_grp_attr_alloc_init();
  lck_grp_attr_setstat(osquery.lck_grp_attr);
  osquery.lck_grp = lck_grp_alloc_init("osquery", osquery.lck_grp_attr);
  osquery.lck_attr = lck_attr_alloc_init();

  // MTX is the IOCTL API handling lock.
  // This assures only one daemon will use the kernel API simultaneously.
  osquery.mtx = lck_mtx_alloc_init(osquery.lck_grp, osquery.lck_attr);
}

static inline void teardown_locks() {
  // Release locks and their heap memory.
  lck_mtx_free(osquery.mtx, osquery.lck_grp);

  lck_attr_free(osquery.lck_attr);
  lck_grp_free(osquery.lck_grp);
  lck_grp_attr_free(osquery.lck_grp_attr);
}

static void unsubscribe_all_events() {
  for (int i = 0; i < OSQUERY_NUM_EVENTS; i++) {
    if (osquery_publishers[i]) {
      osquery_publishers[i]->unsubscribe();
    }
  }
}

static int subscribe_to_event(osquery_event_t event, int subscribe) {
  if (osquery.buffer == NULL) {
    return -EINVAL;
  }
  if (!(OSQUERY_NULL_EVENT < event && event < OSQUERY_NUM_EVENTS)) {
    return -EINVAL;
  }
  if (!osquery_publishers[event]) {
    return -EINVAL;
  }

  if (subscribe) {
    if (osquery_publishers[event]->subscribe(&osquery.cqueue)) {
      return -EINVAL;
    }
  } else {
    osquery_publishers[event]->unsubscribe();
  }

  return 0;
}

static int update_user_kernel_buffer(int options,
                                     size_t read_offset,
                                     size_t *max_read_offset,
                                     int *drops) {
  if (osquery_cqueue_advance_read(
          &osquery.cqueue, read_offset, max_read_offset)) {
    return -EINVAL;
  }
  if (!(options & OSQUERY_OPTIONS_NO_BLOCK)) {
    ssize_t offset = 0;
    if ((offset = osquery_cqueue_wait_for_data(&osquery.cqueue)) < 0) {
      return -EINVAL;
    }

    *max_read_offset = offset;
  }
  *drops = osquery_cqueue_dropped_data(&osquery.cqueue);
  return 0;
}

static void cleanup_user_kernel_buffer() {
  osquery_cqueue_destroy(&osquery.cqueue);

  if (osquery.mm) {
    osquery.mm->release();
    osquery.mm = NULL;
  }

  if (osquery.md) {
    osquery.md->release();
    osquery.md = NULL;
  }

  if (osquery.buffer) {
    IOFreeAligned(osquery.buffer, osquery.buf_size);
    osquery.buffer = NULL;
  }
}

static int allocate_user_kernel_buffer(size_t size, void **buf) {
  int err{0};

  // The user space daemon is requesting a new circular queue.
  // Make sure the requested size is within sane size bounds.
  if (size > MAX_KMEM || size < MIN_KMEM) {
    err = -EINVAL;
    goto error_exit;
  }

  // Record the requested buffer size.
  osquery.buf_size = size;
  // Allocate a contiguous region of memory.
  osquery.buffer = IOMallocAligned(osquery.buf_size, PAGE_SIZE);
  // Cannot proceed if no memory to back the circular queue is available.
  if (osquery.buffer == NULL) {
    err = -EINVAL;
    goto error_exit;
  }

  // Zero memory for safety, this memory will be shared with user space.
  bzero(osquery.buffer, osquery.buf_size);

  // This buffer will be shared, create a descriptor.
  osquery.md =
      IOMemoryDescriptor::withAddressRange((mach_vm_address_t)osquery.buffer,
                                           osquery.buf_size,
                                           kIODirectionInOut,
                                           kernel_task);
  if (osquery.md == NULL) {
    err = -EINVAL;
    goto error_exit;
  }

  // Now map the buffer into the user space process as read only.
  osquery.mm = osquery.md->createMappingInTask(
      current_task(), NULL, kIOMapAnywhere | kIOMapReadOnly);
  if (osquery.mm == NULL) {
    err = -EINVAL;
    goto error_exit;
  }

  // The virtual address will be shared back to the user space queue manager.
  *buf = (void *)osquery.mm->getAddress();
  // Initialize the kernel space queue manager with the new buffer.
  osquery_cqueue_init(&osquery.cqueue, osquery.buffer, osquery.buf_size);

  return 0;
error_exit:
  // A drop-through error handler will clean up any intermediate allocations.
  cleanup_user_kernel_buffer();

  return err;
}

static int osquery_open(dev_t dev, int oflags, int devtype, struct proc *p) {
  // Close is not working so leave these out for now.
  int err{0};
  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count == 0) {
    osquery.open_count++;
  }
#ifndef KERNEL_TEST
  else {
    err = -EACCES;
  }
#endif // !KERNEL_TEST

  lck_mtx_unlock(osquery.mtx);
  return err;
}

static int osquery_close(dev_t dev, int flag, int fmt, struct proc *p) {
  // Only one daemon should request a close.
  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count == 1) {
    unsubscribe_all_events();
    cleanup_user_kernel_buffer();
    osquery.open_count--;
  }
  lck_mtx_unlock(osquery.mtx);

  return 0;
}

static int osquery_ioctl(
    dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p) {
#ifdef KERNEL_TEST
  // Reentrant code used for testing the queue functionality.
  // This test-only code allows benchmarks to stress test queue handling.
  static unsigned int test_counter = 0;
  if (cmd == OSQUERY_IOCTL_TEST) {
    if (osquery.buffer == NULL) {
      return -EINVAL;
    }
    test_counter++;

    size_t length = 0;
    void *e = NULL;
    switch (*(int *)data) {
    case 0:
      e = osquery_cqueue_reserve(
          &osquery.cqueue, OSQUERY_TEST_EVENT_0, sizeof(test_event_0_data_t));
      length = 4096;
      break;
    case 1:
      e = osquery_cqueue_reserve(
          &osquery.cqueue, OSQUERY_TEST_EVENT_1, sizeof(test_event_1_data_t));
      length = 33;
      break;
    default:
      return -ENOTTY;
    }
    if (!e) {
      return -EINVAL;
    }

    *(int *)e = test_counter;
    char *s = (char *)((int *)e + 1);
    memset(s, 'H', length);

    osquery_cqueue_commit(&osquery.cqueue, e);

    return 0;
  }
#endif // KERNEL_TEST

  int err{0};
  osquery_subscription_args_t *sub = NULL;
  osquery_buf_sync_args_t *sync = NULL;
  osquery_buf_allocate_args_t *alloc = NULL;

  // All control should be from a single daemon.
  // Wrap all IOCTL API handling in locks to guarantee proper use.
  lck_mtx_lock(osquery.mtx);
  switch (cmd) {
  // Daemon is requesting a new subscription (e.g., monitored path).
  case OSQUERY_IOCTL_SUBSCRIPTION:
    sub = (osquery_subscription_args_t *)data;
    if ((err = subscribe_to_event(sub->event, sub->subscribe))) {
      goto error_exit;
    }
    break;

  // Daemon is requesting a synchronization of readable queue space.
  case OSQUERY_IOCTL_BUF_SYNC:
    // The queue buffer cannot be synchronized if it has not been allocated.
    if (osquery.buffer == NULL) {
      err = -EINVAL;
      goto error_exit;
    }

    // Unlock while applying update logic, re-lock on error and success.
    lck_mtx_unlock(osquery.mtx);
    sync = (osquery_buf_sync_args_t *)data;
    if ((err = update_user_kernel_buffer(sync->options,
                                         sync->read_offset,
                                         &(sync->max_read_offset),
                                         &(sync->drops)))) {
      lck_mtx_lock(osquery.mtx);
      goto error_exit;
    }
    lck_mtx_lock(osquery.mtx);
    break;

  // Daemon is requesting an allocation for the queue, and shared region.
  case OSQUERY_IOCTL_BUF_ALLOCATE:
    alloc = (osquery_buf_allocate_args_t *)data;
    if (alloc->version != OSQUERY_KERNEL_COMM_VERSION) {
      // Daemon tried connecting with incorrect version number.
      // The structure types and sizes are bound to the COMMs version.
      // Any non-matching daemon may not handle these structures correctly.
      err = -EINVAL;
      goto error_exit;
    }

    if (osquery.buffer != NULL) {
      // There is only a single shared buffer.
      err = -EINVAL;
      goto error_exit;
    }

    // Attempt to allocation and set up the circular queue.
    if ((err = allocate_user_kernel_buffer(alloc->size, &(alloc->buffer)))) {
      goto error_exit;
    }

    dbg_printf(
        "IOCTL alloc: size %lu, location %p\n", alloc->size, alloc->buffer);
    break;
  default:
    err = -ENOTTY;
    goto error_exit;
    break;
  }

error_exit:
  // Unlock and return a status to the daemon.
  lck_mtx_unlock(osquery.mtx);
  return err;
}

// OSQuery character device switch structure.
static struct cdevsw osquery_cdevsw = {
    osquery_open, // open_close_fcn_t *d_open;
    osquery_close, // open_close_fcn_t *d_close;
    eno_rdwrt, // read_write_fcn_t *d_read;
    eno_rdwrt, // read_write_fcn_t *d_write;
    &osquery_ioctl, // ioctl_fcn_t      *d_ioctl;
    eno_stop, // stop_fcn_t       *d_stop;
    eno_reset, // reset_fcn_t      *d_reset;
    NULL, // struct tty      **d_ttys;
    eno_select, // select_fcn_t     *d_select;
    eno_mmap, // mmap_fcn_t       *d_mmap;
    eno_strat, // strategy_fcn_t   *d_strategy;
    eno_getc, // getc_fcn_t       *d_getc;
    eno_putc, // putc_fcn_t       *d_putc;
    0 // int               d_type;
};

kern_return_t OsqueryStart(kmod_info_t *ki, void *d) {
  dbg_printf("Kernel module starting!\n");

  // Restart the queue and setup queue locks.
  // This does not allocate, share, or set the queue buffer or buffer values.
  osquery_cqueue_setup(&osquery.cqueue);

  // Initialize the IOCTL (and more) device node.
  osquery.major_number = cdevsw_add(osquery.major_number, &osquery_cdevsw);
  if (osquery.major_number < 0) {
    dbg_printf("Could not get a major number!\n");
    goto error_exit;
  }

  // Create the IOCTL (and more) device node.
  osquery.devfs = devfs_make_node(makedev(osquery.major_number, 0),
                                  DEVFS_CHAR,
                                  UID_ROOT,
                                  GID_WHEEL,
                                  0600,
                                  "osquery",
                                  0);
  if (osquery.devfs == NULL) {
    dbg_printf("Could not get a devfs entry!\n");
    goto error_exit;
  }

  // Set up the IOCTL and kernel API locks (not queue locks).
  setup_locks();

  return KERN_SUCCESS;
error_exit:
  // Upon error, remove the device node if it was allocated.
  if (osquery.devfs != NULL) {
    devfs_remove(osquery.devfs);
    osquery.devfs = NULL;
  }

  // Tear down device node data.
  if (!(osquery.major_number < 0)) {
    if (cdevsw_remove(osquery.major_number, &osquery_cdevsw) < 0) {
      panic("osquery kext: Cannot remove osquery from cdevsw");
    }
  }

  // Reset the queue and remove the queue locks.
  osquery_cqueue_teardown(&osquery.cqueue);
  return KERN_FAILURE;
}

kern_return_t OsqueryStop(kmod_info_t *ki, void *d) {
  dbg_printf("Kernel module stopping!\n");

  // Only stop if there are no connected daemons.
  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count > 0) {
    lck_mtx_unlock(osquery.mtx);
    return KERN_FAILURE;
  }

  // Stop sharing the queue and remove queue locks.
  // This will potentially block as heuristics are applied to make sure the
  // queue is no longer is use.
  if (osquery_cqueue_teardown(&osquery.cqueue)) {
    lck_mtx_unlock(osquery.mtx);
    return KERN_FAILURE;
  }

  // Remove the device node.
  devfs_remove(osquery.devfs);
  osquery.devfs = NULL;

  // Tear down the device node data.
  if (cdevsw_remove(osquery.major_number, &osquery_cdevsw) < 0) {
    panic("osquery kext: Cannot remove osquery from cdevsw");
  }

  // Deallocate the IOCTL and kernel API locks.
  lck_mtx_unlock(osquery.mtx);
  teardown_locks();

  return KERN_SUCCESS;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
}

KMOD_EXPLICIT_DECL(com.facebook.security.osquery,
                   STR(OSQUERY_KERNEL_COMMUNICATION_VERSION),
                   _start,
                   _stop)
DECLHIDDEN(kmod_start_func_t *) _realmain = OsqueryStart;
DECLHIDDEN(kmod_stop_func_t *) _antimain = OsqueryStop;
DECLHIDDEN(int) _kext_apple_cc = __APPLE_CC__;
