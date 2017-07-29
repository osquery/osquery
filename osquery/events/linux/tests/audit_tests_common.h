#pragma once

#include <cstring>
#include <string>

namespace osquery {
/// Generates a fake audit id
std::string generateAuditId(std::uint32_t event_id) noexcept;
}