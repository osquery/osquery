#pragma once
#include "osquery/core/conversions.h"
#include <Windows.h>

#include "accctrl.h"
#include "aclapi.h"
#pragma comment(lib, "advapi32.lib")

namespace osquery {

std::string getFileAttribStr(ULONG);
time_t FileTimeToUnixTime(FILETIME&);
time_t LongIntToUnixTime(LARGE_INTEGER&);
}