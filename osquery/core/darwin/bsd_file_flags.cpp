#include <iomanip>
#include <unordered_map>

#include <boost/algorithm/string/join.hpp>

#include <sys/stat.h>

#include "osquery/core/utils.h"

namespace osquery {
namespace {
/// The list of supported flags, as documented in `man 2 chflags`
const std::unordered_map<std::uint32_t, std::string> kBsdFlagMap = {
    {UF_NODUMP, "NODUMP"},
    {UF_IMMUTABLE, "UF_IMMUTABLE"},
    {UF_APPEND, "UF_APPEND"},
    {UF_OPAQUE, "OPAQUE"},
    {UF_HIDDEN, "HIDDEN"},
    {SF_ARCHIVED, "ARCHIVED"},
    {SF_IMMUTABLE, "SF_IMMUTABLE"},
    {SF_APPEND, "SF_APPEND"}};

std::uint32_t getBsdFlagMask() {
  std::uint32_t result = 0U;

  for (const auto& p : kBsdFlagMap) {
    const auto& bit = p.first;
    result |= bit;
  }

  return result;
}
} // namespace

/// Builds a list of the known BSD file flags specified by st_flags (see the
/// stat structure). Foreign bits are added to the list as a hexadecimal number
Status describeBSDFileFlags(std::string& output, std::uint32_t st_flags) {
  output.clear();

  static const auto flag_mask = getBsdFlagMask();

  std::vector<std::string> label_list;

  for (const auto& p : kBsdFlagMap) {
    const auto& bit = p.first;
    const auto& label = p.second;

    if ((st_flags & bit) != 0U) {
      label_list.push_back(label);
    }
  }

  auto foreign_bits = st_flags & (~flag_mask);
  if (foreign_bits != 0U) {
    std::stringstream buffer;
    buffer << "0x" << std::setw(8) << std::setfill('0') << std::hex
           << foreign_bits;

    label_list.push_back(buffer.str());
  }

  output = boost::algorithm::join(label_list, ", ");

  if (foreign_bits != 0U) {
    return Status::failure("Foreign bits were found in the st_flags field");
  }

  return Status(0);
}
} // namespace osquery
