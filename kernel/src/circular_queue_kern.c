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

#include <sys/proc.h>

#include <kern/assert.h>


#include "circular_queue_kern.h"

static inline void setup_locks(osquery_cqueue_t *queue) {
  /* Create locks.  Cannot be done on the stack. */
  queue->lck_grp_attr = lck_grp_attr_alloc_init();
  lck_grp_attr_setstat(queue->lck_grp_attr);

  queue->lck_grp = lck_grp_alloc_init("osquery cqueue", queue->lck_grp_attr);

  queue->lck_attr = lck_attr_alloc_init();

  queue->lck = lck_spin_alloc_init(queue->lck_grp, queue->lck_attr);
}

static inline void destroy_locks(osquery_cqueue_t *queue) {
  lck_spin_free(queue->lck, queue->lck_grp);

  lck_attr_free(queue->lck_attr);

  lck_grp_free(queue->lck_grp);

  lck_grp_attr_free(queue->lck_grp_attr);
}

static inline void *advance_pointer(osquery_cqueue_t *queue, void *ptr,
                                    size_t bytes) {
  return ((uint8_t *)ptr + bytes - queue->buffer) % queue->size + queue->buffer;
}

static inline size_t get_distance(osquery_cqueue_t *queue, void *lower,
                                  void *upper, int cannot_be_empty) {
  ssize_t size = (uint8_t *)upper - (uint8_t *)lower;
  if (size == 0) {
    return cannot_be_empty ? queue->size : 0;
  } else if (size < 0) {
    return queue->size + size;
  } else {
    return size;
  }
}

typedef enum {
  OSQUERY_BETWEEN_INIT = 0,
  OSQUERY_BETWEEN = 1,
  OSQUERY_NOT_BETWEEN = 1 << 1,
  OSQUERY_NOT_IN_BUFFER = 1 << 2
} osquery_between_t;

static inline osquery_between_t is_between(osquery_cqueue_t *queue, void *ptr,
                                           void *lower, void *upper,
                                           size_t size) {
  osquery_between_t b = OSQUERY_BETWEEN_INIT;
  if (ptr < (void *)queue->buffer
      || ((uint8_t *)ptr) + size > (queue->buffer + queue->size)) {
    b |= OSQUERY_NOT_IN_BUFFER;
  }

  if (lower <= upper && lower <= ptr
      && ((void *)(((uint8_t *)ptr) + size)) <= upper) {
    b |= OSQUERY_BETWEEN;
  } else if (upper < lower
             && (((void *)(((uint8_t *)ptr) + size)) <= upper || lower <= ptr)) {
    b |= OSQUERY_BETWEEN;
  } else {
    b |= OSQUERY_NOT_BETWEEN;
  }

  return b;
}

void osquery_cqueue_init(osquery_cqueue_t *queue, void *buffer, size_t size) {
  setup_locks(queue);

  queue->buffer = (uint8_t *)buffer;
  queue->size = size;

  queue->write = queue->buffer;
  queue->max_read = queue->buffer;
  queue->read = queue->buffer;

  queue->drops = 0;
  queue->initialized = 1;
}

void osquery_cqueue_destroy(osquery_cqueue_t *queue) {
  if (queue->initialized) {
    queue->initialized = 0;
    destroy_locks(queue);
  }
}

int osquery_cqueue_advance_read(osquery_cqueue_t *queue, size_t read_offset,
                                size_t *max_read_offset) {
  if (!queue->initialized) {
    return -1;
  }
  int err = 0;
  lck_spin_lock(queue->lck);

  uint8_t *new_read = queue->buffer + read_offset;
  if (OSQUERY_BETWEEN == is_between(queue, new_read, queue->read,
                                    queue->max_read, 0)) {
    queue->read = new_read;
  } else {
    queue->read = queue->max_read;
    err = -1;
  }
  *max_read_offset = queue->max_read - queue->buffer;

  lck_spin_unlock(queue->lck);

  return err;
}

ssize_t osquery_cqueue_wait_for_data(osquery_cqueue_t *queue) {
  if (!queue->initialized) {
    return -1;
  }
  wait_result_t wait_result = THREAD_AWAKENED;

  lck_spin_lock(queue->lck);
  while (wait_result == THREAD_AWAKENED && queue->max_read == queue->read) {
    wait_result = lck_spin_sleep(queue->lck, LCK_SLEEP_DEFAULT,
                                 &queue->max_read, THREAD_ABORTSAFE);
  }
  size_t offset = queue->max_read - queue->buffer;
  
  lck_spin_unlock(queue->lck);
  return offset;
}

int osquery_cqueue_dropped_data(osquery_cqueue_t *queue) {
  int drops;
  if (!queue->initialized) {
    return -1;
  }

  lck_spin_lock(queue->lck);
  drops = queue->drops;
  queue->drops = 0;
  lck_spin_unlock(queue->lck);

  return drops;
}

void *osquery_cqueue_reserve(osquery_cqueue_t *queue, osquery_event_t event) {
  if (!queue->initialized) {
    return NULL;
  }
  
  void *ret = NULL;
  osquery_data_header_t *header = NULL;

  size_t size = osquery_sizeof_event(event) + sizeof(osquery_data_header_t);

  lck_spin_lock(queue->lck);
  
  // We do not want the write pointer to ever equal the read pointer unless
  // everything is empty.  Otherwise we need to track the empty states for the
  // buffer.
  if (get_distance(queue, queue->write, queue->read, 1) > size) {
    if (get_distance(queue, queue->write,
                     queue->buffer + queue->size, 0) >= size) {
      // We can fit the allocation by advancing the write pointer.
      header = (osquery_data_header_t *)queue->write;
      queue->write = (uint8_t *)advance_pointer(queue, queue->write, size);
    } else if (get_distance(queue, queue->buffer, queue->read, 0) > size) {
      // We can fit the allocation by wrapping the write pointer.
      if (get_distance(queue, queue->write, queue->buffer + queue->size, 0)
          >= sizeof(osquery_data_header_t)) {
        // Signal a Null event ie. jump to beginning of buf.  If there
        // is not enough room to do so, this is ok because it will know to
        // skip to the beginning of the buffer based on the amount of space
        // left.
        header = (osquery_data_header_t *)queue->write;
        header->event = END_OF_BUFFER_EVENT;
      }
      header = (osquery_data_header_t *)queue->buffer;
      queue->write = (uint8_t *)advance_pointer(queue, queue->buffer, size);
    }
  }

  if (header) {
    header->event = event;
    header->finished = 0;

    // Give them the pointer to the space not the header.
    ret = (void *)(header + 1);
  } else {
    if (queue->drops >= 0) {
      queue->drops += 1;
    }
    ret = NULL;
  }

  lck_spin_unlock(queue->lck);

  return ret;
}

/** @brief Turn blocks that have been commited into readable space for user
 *  level process.
 *
 *  REQUIRES the lock.
 *
 *  @param queue The queue to create readable space in.
 *  @return Void.
 */
static inline void coalesce_readable(osquery_cqueue_t *queue) {
  osquery_data_header_t *header = (osquery_data_header_t *)queue->max_read;
  osquery_between_t b;

  while (OSQUERY_BETWEEN & (b = is_between(queue, header, queue->max_read,
                                       queue->write, sizeof(osquery_data_header_t)))) {
    if (b & OSQUERY_NOT_IN_BUFFER || header->event == END_OF_BUFFER_EVENT) {
      queue->max_read = queue->buffer;
      header = (osquery_data_header_t *)queue->max_read;
      continue;
    } else if (!header->finished) {
      break;
    }

    queue->max_read = (uint8_t *)advance_pointer(queue, queue->max_read,
                                      osquery_sizeof_event(header->event)
                                      + sizeof(osquery_data_header_t));
  
    header = (osquery_data_header_t *)queue->max_read;
    wakeup(&queue->max_read);

    lck_spin_unlock(queue->lck);
    lck_spin_lock(queue->lck);
  }
}

int osquery_cqueue_commit(osquery_cqueue_t *queue, void *space) {
  if (!queue->initialized) {
    return -1;
  }
  int err = 0;

  lck_spin_lock(queue->lck);

  // Retrieve the header for the initialized space.
  osquery_data_header_t *header = ((osquery_data_header_t *)space) - 1;
  if (OSQUERY_BETWEEN != is_between(queue, header, queue->max_read,
                                    queue->write, sizeof(osquery_data_header_t))
      || header->event == END_OF_BUFFER_EVENT
      || header->finished) {
    err = -1;  // Invalid space.
    goto error_exit;
  }

  header->finished = 1;

  coalesce_readable(queue);

error_exit:
  lck_spin_unlock(queue->lck);
  return err;
}

