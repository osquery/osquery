/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

namespace osquery {

/**
 * @brief Launch the scheduler.
 *
 * osquery comes with a scheduler, which schedules a variety of things. This
 * is one of the core parts of the osqueryd daemon. To use this, simply use
 * this function as your entry point when creating a new thread.
 *
 * @code{.cpp}
 *   boost::thread scheduler_thread(osquery::initializeScheduler);
 *   // do some other stuff
 *   scheduler_thread.join();
 * @endcode
 */
void initializeScheduler();

/**
 * @brief Calculate a splayed integer based on a variable splay percentage
 *
 * The value of splayPercent must be between 1 and 100. If it's not, the
 * value of original will be returned.
 *
 * @param original The original value to be modified
 * @param splayPercent The percent in which to splay the original value by
 *
 * @return The modified version of original
 */
int splayValue(int original, int splayPercent);
}
