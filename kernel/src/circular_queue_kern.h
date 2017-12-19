/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */
/** @brief Circular queue implementation for a producer, consumer based setup.
 *
 *  Specifically this circular queue implementation is used for passing event
 *  information from the kernel to the user.
 *
 *
 *  For safety this queue on an error should log the error and reset to a known
 *  safe state possibly dropping all data in held within it.
 *
 */

#pragma once

#include <stdint.h>
#include <sys/lock.h>

#include <kern/clock.h>

#include <feeds.h>

#ifdef __cplusplus
extern "C" {
#endif

// Circular queue data structure.
typedef struct {
  uint8_t *buffer;
  size_t size;
  uint8_t *write;
  uint8_t *max_read;
  uint8_t *read;
  int drops;
  int initialized;
  uint32_t reservations;
  clock_sec_t last_destruction_time;

  lck_grp_attr_t *lck_grp_attr;
  lck_grp_t *lck_grp;
  lck_attr_t *lck_attr;
  lck_spin_t *lck;
} osquery_cqueue_t;

/** @brief Setup a circular queue lock system.
 *
 *  @param queue The circular queue to initialize the locks of.
 *  @return Void.
 */
void osquery_cqueue_setup(osquery_cqueue_t *queue);

/** @brief Teardown the circular queue locking system.
 *
 *  Throws an error if the cqueue is currently initialized, or if it has NOT
 *  been more than 1 second of system uptime since osquery_cqueue_destroy()
 *  finished running.  This should be run at kernel extension unload time, a
 *  priveledged action.  The extension unload should fail if this call fails.
 *  A panic may ensue if the delay of 1 second is satisfied, but all pending
 *  event callbacks have still not finished.
 *
 *  @param queue The queue to teardown the locks for.
 *  @return 0 on success.  Negative due to an error.
 */
int osquery_cqueue_teardown(osquery_cqueue_t *queue);

/** @brief Initialize a circular queue.
 *
 *  Initializes a circular queue given a preallocated buffer of a given size.
 *
 *  @param queue The circular queue structure to initialize.
 *  @param buffer The buffer to use in the queue.
 *  @param size The size of the passed in buffer.
 *  @return Void.
 */
void osquery_cqueue_init(osquery_cqueue_t *queue, void *buffer, size_t size);


/** @brief Cleanup a cqueue.
 *
 *  This waits till there are no pending events.  ie. it blocks till the kernel
 *  cannot possibly be writing to the buffer.  This means, after this function
 *  call, it is safe to deallocate the buffer used by the queue.  This
 *  function additionally records the system uptime of when it exits so we can
 *  try to guarantee that osquery_cqueue_teardown() does not come along and free
 *  the cqueue locks before lingering event callbacks finish executing.  We do
 *  this by having osquery_cqueue_teardown() fail if it is being called too soon
 *  after the return from this function.
 *
 *  @param queue The cqueue to destroy.
 *  @return Void.
 */
void osquery_cqueue_destroy(osquery_cqueue_t *queue);


/** @brief Advance the read head in the buffer.
 *
 *  @param queue The circular queue structure to advance the read head in.
 *  @param read_offset Offset of pointer to new location of read head.
 *  @param max_read_offset (Output) Output the offset of the max_read pointer.
 *  @return Return negative on failure (invalid offset).
 */
int osquery_cqueue_advance_read(osquery_cqueue_t *queue, size_t read_offset,
                                size_t *max_read_offset);


/** @brief Find the position of the max_read pointer.  Block if buffer is empty.
 *
 *  @param queue The queue to find the offset of the max_read pointer in.
 *  @return Return offset of max_read pointer.  Negative on failure.
 */
ssize_t osquery_cqueue_wait_for_data(osquery_cqueue_t *queue);

/** @brief Returns if the cqueue has dropped data.
 *
 *  Returns whether data has been dropped since the last call of this function.
 *
 *  @param queue The cqueue to look for dropped data in.
 *  @return 0 for no data dropped 1 for dropped data.
 */
int osquery_cqueue_dropped_data(osquery_cqueue_t *queue);

/** @brief Reserve space to store an event in the queue.
 *
 *  This gives you a brief moment to write data to the returned space.
 *  NOTE: You must call the commit function on your pointer shortly after
 *  reserving it.  Otherwise the buffer will become deadlocked.
 *
 *  @param queue The queue to reserve space in.
 *  @param event The event type to reserve space for.
 *  @param size The size of the event data.
 *  @return Pointer to the space.  NULL if no space could be arranged.
 */
void *osquery_cqueue_reserve(osquery_cqueue_t *queue,
                             osquery_event_t event,
                             size_t size);

/** @brief Commit a write to a previously reserved space.
 *
 *  After commiting your space you may no longer access it.
 *  All reserved spaces must be committed shortly after being
 *  reserved.
 *
 *  @param queue The queue to commit the space in.
 *  @param space The space to commit.
 *  @return Negative on failure (invalid space or cqueue).
 */
int osquery_cqueue_commit(osquery_cqueue_t *queue, void *space);

#ifdef __cplusplus
}  // end extern "c"
#endif

