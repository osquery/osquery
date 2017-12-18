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

#include <sys/proc.h>

#include <kern/assert.h>

#include "circular_queue_kern.h"

static inline void setup_queue_locks(osquery_cqueue_t *queue) {
  /* Create locks.  Cannot be done on the stack. */
  queue->lck_grp_attr = lck_grp_attr_alloc_init();
  lck_grp_attr_setstat(queue->lck_grp_attr);

  queue->lck_grp = lck_grp_alloc_init("osquery cqueue", queue->lck_grp_attr);

  queue->lck_attr = lck_attr_alloc_init();

  queue->lck = lck_spin_alloc_init(queue->lck_grp, queue->lck_attr);
}

static inline void teardown_queue_locks(osquery_cqueue_t *queue) {
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

void osquery_cqueue_setup(osquery_cqueue_t *queue) {
  queue->last_destruction_time = 0;
  queue->initialized = 0;
  setup_queue_locks(queue);
}

int osquery_cqueue_teardown(osquery_cqueue_t *queue) {
  lck_spin_lock(queue->lck);

  // We make sure that the queue hasn't been serving requests for at least 1
  // second before we free up our locks.  This is in an attempt to make sure
  // that lingering event callbacks are all finished before we teardown the
  // locks.
  //
  // 2 seconds of time is used because of the seconds value is floored, and
  // we want this to not succeed for at least one second after
  // osquery_cqueue_destroy()
  clock_sec_t seconds;
  clock_usec_t micro_sec;
  clock_get_system_microtime(&seconds, &micro_sec);
  if (!queue->initialized && seconds > 2 + queue->last_destruction_time) {
    lck_spin_unlock(queue->lck);
    teardown_queue_locks(queue);
    return 0;
  } else {
    lck_spin_unlock(queue->lck);
    return -1;
  }
}

void osquery_cqueue_init(osquery_cqueue_t *queue, void *buffer, size_t size) {
  lck_spin_lock(queue->lck);
  queue->buffer = (uint8_t *)buffer;
  queue->size = size;

  queue->write = queue->buffer;
  queue->max_read = queue->buffer;
  queue->read = queue->buffer;

  queue->drops = 0;
  queue->initialized = 1;
  queue->reservations = 0;
  lck_spin_unlock(queue->lck);
}

void osquery_cqueue_destroy(osquery_cqueue_t *queue) {
  lck_spin_lock(queue->lck);
  if (queue->initialized) {
    queue->initialized = 0;

    while (queue->reservations > 0) {
      lck_spin_sleep(queue->lck, LCK_SLEEP_DEFAULT, &queue->reservations,
                     THREAD_UNINT);
    }

    // Time is recorded so we can fail cqueue_teardown (destruction of cqueue
    // locks) for a short period of time.  This should allow pending event
    // callbacks to notice ths cqueue has been unitialized and error out before
    // the locks become unusable.
    clock_usec_t micro_sec;
    clock_get_system_microtime(&queue->last_destruction_time, &micro_sec);
  }

  lck_spin_unlock(queue->lck);
}

int osquery_cqueue_advance_read(osquery_cqueue_t *queue, size_t read_offset,
                                size_t *max_read_offset) {
  int err = 0;
  lck_spin_lock(queue->lck);

  if (!queue->initialized) {
    err = -1;
    goto error_exit;
  }

  uint8_t *new_read = queue->buffer + read_offset;
  if (OSQUERY_BETWEEN == is_between(queue, new_read, queue->read,
                                    queue->max_read, 0)) {
    queue->read = new_read;
  } else {
    queue->read = queue->max_read;
    err = -1;
  }
  *max_read_offset = queue->max_read - queue->buffer;

error_exit:
  lck_spin_unlock(queue->lck);

  return err;
}

ssize_t osquery_cqueue_wait_for_data(osquery_cqueue_t *queue) {
  ssize_t offset = 0;
  lck_spin_lock(queue->lck);

  if (!queue->initialized) {
    offset = -1;
    goto error_exit;
  }

  wait_result_t wait_result = THREAD_AWAKENED;
  while (wait_result == THREAD_AWAKENED && queue->max_read == queue->read) {
    wait_result = lck_spin_sleep(queue->lck, LCK_SLEEP_DEFAULT,
                                 &queue->max_read, THREAD_ABORTSAFE);
  }
  offset = queue->max_read - queue->buffer;

error_exit:
  lck_spin_unlock(queue->lck);
  return offset;
}

int osquery_cqueue_dropped_data(osquery_cqueue_t *queue) {
  int drops;
  lck_spin_lock(queue->lck);
  if (!queue->initialized) {
    drops = -1;
    goto error_exit;
  }

  drops = queue->drops;
  queue->drops = 0;

error_exit:
  lck_spin_unlock(queue->lck);

  return drops;
}

void *osquery_cqueue_reserve(osquery_cqueue_t *queue,
                             osquery_event_t event,
                             size_t size) {
  void *ret = NULL;
  lck_spin_lock(queue->lck);
  if (!queue->initialized) {
    ret = NULL;
    goto error_exit;
  }

  osquery_data_header_t *header = NULL;

  size_t contents_size = size;
  size += sizeof(osquery_data_header_t);

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
    header->size = contents_size;
    header->finished = 0;

    // Give them the pointer to the space not the header.
    ret = (void *)(header + 1);
    queue->reservations++;
  } else {
    if (queue->drops >= 0) {
      queue->drops += 1;
    }
    ret = NULL;
  }
error_exit:
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

    queue->max_read = (uint8_t *)advance_pointer(
        queue, queue->max_read, header->size + sizeof(osquery_data_header_t));

    header = (osquery_data_header_t *)queue->max_read;
    wakeup(&queue->max_read);

    lck_spin_unlock(queue->lck);
    lck_spin_lock(queue->lck);
  }
}

int osquery_cqueue_commit(osquery_cqueue_t *queue, void *space) {
  int err = 0;

  lck_spin_lock(queue->lck);

  // Retrieve the header for the initialized space.
  osquery_data_header_t *header = ((osquery_data_header_t *)space) - 1;
  if (OSQUERY_BETWEEN != is_between(queue, header, queue->max_read,
                                    queue->write,
                                    sizeof(osquery_data_header_t)) ||
      queue->reservations == 0 || header->event == END_OF_BUFFER_EVENT ||
      header->finished) {
    err = -1;  // Invalid space.
    goto error_exit;
  }

  header->finished = 1;
  clock_sec_t seconds;
  clock_usec_t microsecs;
  clock_get_calendar_microtime(&seconds, &microsecs);
  header->time.time = (uint64_t)seconds;
  clock_get_system_microtime(&seconds, &microsecs);
  header->time.uptime = (uint64_t)seconds;

  coalesce_readable(queue);

  queue->reservations--;
  wakeup(&queue->reservations);
error_exit:
  lck_spin_unlock(queue->lck);
  return err;
}

