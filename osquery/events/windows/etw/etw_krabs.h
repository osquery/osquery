/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include "krabs.hpp"

namespace osquery {

// Kilobytes of memory allocated for each event tracing session buffer.
static const ULONG kEventTraceBufferSize = 256;

// Minimum number of buffers reserved for the tracing session's buffer pool.
static const ULONG kEventTraceMinimumBuffers = 12;

// Maximum number of buffers to be allocated for the session's buffer pool.
static const ULONG kEventTraceMaximumBuffers = 48;

// How often, in seconds, any non-empty trace buffers are flushed
static const ULONG kEventTraceFlushTimer = 1;

// The following constants represent the possible logging modes for an event
// tracing session.
// EVENT_TRACE_REAL_TIME_MODE: Delivers the events to consumers in real-time.
// EVENT_TRACE_INDEPENDENT_SESSION_MODE: Indicates that a logging session should
// not be affected by EventWrite failures in other sessions.
static const ULONG kEventTraceLogFileMode =
    EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_INDEPENDENT_SESSION_MODE;

} // namespace osquery