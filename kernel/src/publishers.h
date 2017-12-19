/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <feeds.h>

#include "circular_queue_kern.h"

/** @brief Subscribe function type.
 *
 *  This function type is called when someone subscribes to a publisher.  It
 *  should initialize all event callbacks and start publishing events to the
 *  queue.
 *
 *  @param queue The queue to publish to.  A subscriber will only publish to the
 *         last queue (not an issue as there should only be one queue).
 *  @return 0 on success, negative on failure.
 */
typedef int (*osquery_subscriber_t)(osquery_cqueue_t *queue);
/** @brief Unsubscribe function type.
 *
 *  Functions of this type stop a publisher from publishing events to the queue
 *  as soon as possible.
 *
 *  @return Void.
 */
typedef void (*osquery_unsubscriber_t)();

/** @brief A kernel publisher must provide the following function pointers.
 */
typedef struct {
  osquery_subscriber_t subscribe;
  osquery_unsubscriber_t unsubscribe;
} osquery_kernel_event_publisher_t;

//
// Event publisher structs defined in implementations.
//
extern osquery_kernel_event_publisher_t process_events_publisher;
extern osquery_kernel_event_publisher_t kernel_file_events_publisher;

/** @brief List of the kernel event publishers.
 */
static osquery_kernel_event_publisher_t *
    osquery_publishers[OSQUERY_NUM_EVENTS] =
        {[OSQUERY_PROCESS_EVENT] = &process_events_publisher,
         [OSQUERY_FILE_EVENT] = &kernel_file_events_publisher};
