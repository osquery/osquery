/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
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

#include <feeds.h>

#ifdef __cplusplus
extern "C" {
#endif

// Circular queue data structure.
typedef struct osquery_cqueue {
  uint8_t *buffer;
  size_t size;
  uint8_t *write;
  uint8_t *max_read;
  uint8_t *read;
  int drops;
  int initialized;

  lck_grp_attr_t *lck_grp_attr;
  lck_grp_t *lck_grp;
  lck_attr_t *lck_attr;
  lck_spin_t *lck;
} osquery_cqueue_t;


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
 *  @return Pointer to the space.  NULL if no space could be arranged.
 */
void *osquery_cqueue_reserve(osquery_cqueue_t *queue, osquery_event_t event);


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

