
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

namespace osquery {

/**
 * @brief EventSubscriber%s and Publishers may exist in various states.
 *
 * The class will move through states when osquery is initializing the
 * registry, starting event publisher loops, and requesting initialization of
 * each subscriber and the optional set of subscriptions it creates. If this
 * initialization fails the publishers or EventFactory may eject, warn, or
 * otherwise not use the subscriber's subscriptions.
 *
 * The supported states are:
 * - None: The default state, uninitialized.
 * - Setup: The Subscriber is attached and has run setup.
 * - Running: Subscriber is ready for events.
 * - Paused: Subscriber was initialized but is not currently accepting events.
 * - Failed: Subscriber failed to initialize or is otherwise offline.
 */
enum class EventState {
  EVENT_NONE = 0,
  EVENT_SETUP,
  EVENT_RUNNING,
  EVENT_PAUSED,
  EVENT_FAILED,
};

class Eventer {
 public:
  /**
   * @brief Request the subscriber's initialization state.
   *
   * When event subscribers are created (initialized) they are expected to emit
   * a set of subscriptions to their publisher "type". If the subscriber fails
   * to initialize then the publisher may remove any intermediate subscriptions.
   */
  EventState state() const;

 protected:
  /// Set the subscriber state.
  void state(EventState state);

 private:
  /// The event subscriber's run state.
  EventState state_{EventState::EVENT_NONE};

  friend class EventFactory;
};

} // namespace osquery
