/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

namespace osquery {
  /**
   * @brief A helpful tool type to report when logging, print help, or debugging.
   *
   * The Initializer class attempts to detect the ToolType using the tool name
   * and some compile time options.
   */
  enum class ToolType {
    UNKNOWN = 0,
    SHELL,
    DAEMON,
    TEST,
    EXTENSION,
    SHELL_DAEMON,
  };

  /// The osquery tool type for runtime decisions.
  extern ToolType kToolType;
}
