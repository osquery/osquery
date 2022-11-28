/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <boost/optional.hpp>

namespace osquery {

enum class FirmwareKind {
  Bios,
  Uefi,
  iBoot,
  OpenFirmware,
};

boost::optional<FirmwareKind> getFirmwareKind();
const std::string& getFirmwareKindDescription(
    const FirmwareKind& firmware_kind);

} // namespace osquery