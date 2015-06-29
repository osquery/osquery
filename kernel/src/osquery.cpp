/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <libkern/libkern.h>
#include <libkern/OSKextLib.h>
#include <mach/mach_types.h>

#include <kern/debug.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <miscfs/devfs/devfs.h>

// IOKit headers
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOLib.h>

#include <feeds.h>
#include "circular_queue_kern.h"

#ifdef DEBUG
#define dbg_printf(...) printf("OSQUERY KEXT: " __VA_ARGS__)
#else
#define dbg_printf(...) do{ } while(0)
#endif

// Let the major number be decided for us.
#define OSQUERY_MAJOR -1
#define MAX_KMEM (20 * (1 << 20))
#define MIN_KMEM (8 * (1 << 10))


static struct osquery {
  osquery_cqueue_t cqueue;
  void *buffer;
  size_t buf_size;
  IOMemoryDescriptor *md;
  IOMemoryMap *mm;
  void *devfs;
  int major_number;
  int open_count;

  lck_grp_attr_t *lck_grp_attr;
  lck_grp_t *lck_grp;
  lck_attr_t *lck_attr;
  lck_mtx_t *mtx;
} osquery = {
  .open_count = 0,
  .buffer = NULL,
  .buf_size = 0,
  .md = NULL,
  .mm = NULL,
  .devfs = NULL,
  .major_number = OSQUERY_MAJOR
};

static inline void setup_locks() {
  /* Create locks.  Cannot be done on the stack. */
  osquery.lck_grp_attr = lck_grp_attr_alloc_init();
  lck_grp_attr_setstat(osquery.lck_grp_attr);

  osquery.lck_grp = lck_grp_alloc_init("osquery", osquery.lck_grp_attr);

  osquery.lck_attr = lck_attr_alloc_init();

  osquery.mtx = lck_mtx_alloc_init(osquery.lck_grp, osquery.lck_attr);
}

static inline void destroy_locks() {
  lck_mtx_free(osquery.mtx, osquery.lck_grp);

  lck_attr_free(osquery.lck_attr);

  lck_grp_free(osquery.lck_grp);

  lck_grp_attr_free(osquery.lck_grp_attr);
}

static int subscribe_to_event(osquery_event_t event, int subscribe) {
  // TODO: Logic to start a subscription for events of a given type.
  if (osquery.buffer == NULL) {
    return -EINVAL;
  }

  return -EINVAL;
}

static int update_user_kernel_buffer(int options,
                                     size_t read_offset,
                                     size_t *max_read_offset,
                                     int *drops) {
  if (osquery_cqueue_advance_read(&osquery.cqueue,
                                  read_offset,
                                  max_read_offset)) {
    return -EINVAL;
  }
  if (!(options & OSQUERY_NO_BLOCK)) {
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
  if (osquery.mm) {
    osquery.mm->release();
    osquery.mm = NULL;
  }

  if (osquery.md) {
    osquery.md->release();
    osquery.md = NULL;
  }

  osquery_cqueue_destroy(&osquery.cqueue);

  if (osquery.buffer) {
    IOFreeAligned(osquery.buffer, osquery.buf_size);
    osquery.buffer = NULL;
  }
}

static int allocate_user_kernel_buffer(size_t size, void **buf) {
  int err = 0;
  char *s;

  if (size > MAX_KMEM || size < MIN_KMEM) {
    err = -EINVAL;
    goto error_exit;
  }

  osquery.buf_size = size;
  osquery.buffer = IOMallocAligned(osquery.buf_size, PAGE_SIZE);
  if (osquery.buffer == NULL) {
    err = -EINVAL;
    goto error_exit;
  }
  bzero(osquery.buffer, osquery.buf_size);  // Zero memory for safety.

  osquery.md
    = IOMemoryDescriptor::withAddressRange((mach_vm_address_t)osquery.buffer,
                                           osquery.buf_size,
                                           kIODirectionInOut, kernel_task);
  if (osquery.md == NULL) {
    err = -EINVAL;
    goto error_exit;
  }
  osquery.mm = osquery.md->createMappingInTask(current_task(), NULL,
                                               kIOMapAnywhere | kIOMapReadOnly);
  if (osquery.mm == NULL) {
    err = -EINVAL;
    goto error_exit;
  }
  *buf = (void *)osquery.mm->getAddress();

  osquery_cqueue_init(&osquery.cqueue, osquery.buffer, osquery.buf_size);

  return 0;
error_exit:
  cleanup_user_kernel_buffer();

  return err;
}

static int osquery_open(dev_t dev, int oflags, int devtype, struct proc *p) {
  // Close isnt working so leave these out for now.
  int err = 0;
  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count == 0) {
    osquery.open_count ++;
  }
#ifndef KERNEL_TEST
  else {
    err = -EACCES;
    goto error_exit;
  }
#endif // !KERNEL_TEST

error_exit:
  lck_mtx_unlock(osquery.mtx);
  return err;
}

static int osquery_close(dev_t dev, int flag, int fmt, struct proc *p) {
  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count == 1) {
    osquery.open_count--;
    cleanup_user_kernel_buffer();
  }
  lck_mtx_unlock(osquery.mtx);

  return 0;
}


// All control should be from a single consumer, so we wrap all these calls
// in locks to guarantee proper use.
static int osquery_ioctl(dev_t dev, u_long cmd, caddr_t data,
                         int flag, struct proc *p) {
#ifdef KERNEL_TEST  // Reentrant code used for testing the queue functionality.
  static unsigned int test_counter = 0;
  if (cmd == OSQUERY_IOCTL_TEST) {
    if (osquery.buffer == NULL) {
      return -EINVAL;
    }
    test_counter++;

    void *e = NULL;
    switch (*(int *)data) {
      case 0:
        e = osquery_cqueue_reserve(&osquery.cqueue, OSQUERY_TEST_EVENT_0);
        break;
      case 1:
        e = osquery_cqueue_reserve(&osquery.cqueue, OSQUERY_TEST_EVENT_1);
        break;
      default:
        return -ENOTTY;
    }
    if (!e) {
      return -EINVAL;
    }

    *(int *)e = test_counter;
    char *s = (char *)((int *)e + 1);
    s[0] = 'H';
    s[1] = 'E';
    s[2] = 'L';
    s[3] = 'L';
    s[4] = 'O';
    s[5] = '!';
    s[6] = '\0';

    osquery_cqueue_commit(&osquery.cqueue, e);

    return 0;
  }
#endif // KERNEL_TEST

  lck_mtx_lock(osquery.mtx);

  int err = 0;
  osquery_subscription_args_t *sub = NULL;
  osquery_buf_sync_args_t *sync = NULL;
  osquery_buf_allocate_args_t *alloc = NULL;

  switch (cmd) {
    case OSQUERY_IOCTL_SUBSCRIPTION:
      sub = (osquery_subscription_args_t *)data;
      if ((err = subscribe_to_event(sub->event, sub->subscribe))) {
        goto error_exit;
      }
      break;
    case OSQUERY_IOCTL_BUF_SYNC:
      sync = (osquery_buf_sync_args_t *)data;
      if (osquery.buffer == NULL) {
        err = -EINVAL;
        goto error_exit;
      }
      lck_mtx_unlock(osquery.mtx);
      if ((err = update_user_kernel_buffer(sync->options,
                                           sync->read_offset,
                                           &(sync->max_read_offset),
                                           &(sync->drops)))) {
        lck_mtx_lock(osquery.mtx);
        goto error_exit;
      }
      lck_mtx_lock(osquery.mtx);
      break;
    case OSQUERY_IOCTL_BUF_ALLOCATE:
      alloc = (osquery_buf_allocate_args_t *)data;

      if (osquery.buffer != NULL) {
        // We don't want to allocate a second buffer.
        err = -EINVAL;
        goto error_exit;
      }

      if ((err = allocate_user_kernel_buffer(alloc->size, &(alloc->buffer)))) {
        goto error_exit;
      }

      dbg_printf("IOCTL alloc: size %lu, location %p\n",
                 alloc->size, alloc->buffer);
      break;
    default:
      err = -ENOTTY;
      goto error_exit;
      break;
  }
error_exit:
  lck_mtx_unlock(osquery.mtx);
  return err;
}

// OSQuery character device switch structure.
static struct cdevsw osquery_cdevsw = {
    osquery_open,    // open_close_fcn_t *d_open;
    osquery_close,   // open_close_fcn_t *d_close;
    eno_rdwrt,       // read_write_fcn_t *d_read;
    eno_rdwrt,       // read_write_fcn_t *d_write;
    &osquery_ioctl,  // ioctl_fcn_t      *d_ioctl;
    eno_stop,        // stop_fcn_t       *d_stop;
    eno_reset,       // reset_fcn_t      *d_reset;
    NULL,            // struct tty      **d_ttys;
    eno_select,      // select_fcn_t     *d_select;
    eno_mmap,        // mmap_fcn_t       *d_mmap;
    eno_strat,       // strategy_fcn_t   *d_strategy;
    eno_getc,        // getc_fcn_t       *d_getc;
    eno_putc,        // putc_fcn_t       *d_putc;
    0                // int               d_type;
};

kern_return_t OSQueryStart(kmod_info_t *ki, void *d) {
  dbg_printf("OSQuery kernel module starting!\n");

  osquery.major_number = cdevsw_add(osquery.major_number, &osquery_cdevsw);
  if (osquery.major_number < 0) {
    dbg_printf("Could not get a major number!\n");
    goto error_exit;
  }

  osquery.devfs = devfs_make_node(makedev(osquery.major_number, 0),
                                          DEVFS_CHAR, UID_ROOT, GID_WHEEL,
                                          0644, "osquery", 0);
  if (osquery.devfs == NULL) {
    dbg_printf("Could not get a devfs entry!\n");
    goto error_exit;
  }

  setup_locks();

  return KERN_SUCCESS;
error_exit:
  if (osquery.devfs != NULL) {
    devfs_remove(osquery.devfs);
    osquery.devfs = NULL;
  }

  if (!(osquery.major_number < 0)) {
    if (cdevsw_remove(osquery.major_number, &osquery_cdevsw) < 0) {
      panic("OSQuery kext:  Cannot remove osquery from cdevsw");
    }
  }
  return KERN_FAILURE;
}

kern_return_t OSQueryStop(kmod_info_t *ki, void *d) {
  dbg_printf("OSQuery kernel module stoping!\n");

  lck_mtx_lock(osquery.mtx);
  if (osquery.open_count > 0) {
    lck_mtx_unlock(osquery.mtx);
    return KERN_FAILURE;
  }

  cleanup_user_kernel_buffer();

  devfs_remove(osquery.devfs);
  osquery.devfs = NULL;

  if (cdevsw_remove(osquery.major_number, &osquery_cdevsw) < 0) {
    panic("OSQuery kext:  Cannot remove osquery from cdevsw");
  }

  lck_mtx_unlock(osquery.mtx);
  destroy_locks();

  return KERN_SUCCESS;
}

extern "C" {
extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);
}

KMOD_EXPLICIT_DECL(com.facebook.driver.osquery, VERSION, _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = OSQueryStart;
__private_extern__ kmod_stop_func_t *_antimain = OSQueryStop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;

