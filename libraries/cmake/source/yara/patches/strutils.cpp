#pragma once

#include <stdio.h>
#include <string.h>
#include <yara/strutils.h>

#undef HAVE_STRLCPY
#define HAVE_STRLCPY 0
#undef strlcpy

#undef HAVE_STRLCAT
#define HAVE_STRLCAT 0
#undef strlcat

#undef HAVE_MEMMEM
#define HAVE_MEMMEM 0
#undef memmem

namespace yara_strutils {

#include "strutils.c"

}

extern "C" {

size_t (*yara_strutils_strlcpy)(char* , const char* , size_t ){&yara_strutils::strlcpy};
uint64_t (*yara_strutils_xtoi)(const char*){&yara_strutils::xtoi};
int (*yara_strutils_strnlen_w)(const char*){&yara_strutils::strnlen_w};
size_t (*yara_strutils_strlcpy_w)(char*, const char*, size_t){&yara_strutils::strlcpy_w};
int (*yara_strutils_strcmp_w)(const char*, const char*){&yara_strutils::strcmp_w};
size_t (*yara_strutils_strlcat)(char*, const char*, size_t){&yara_strutils::strlcat};
void *(*yara_strutils_memmem)(const void*, size_t, const void*, size_t){&yara_strutils::memmem};
int (*yara_strutils_isalnum)(const uint8_t*){&yara_strutils::yr_isalnum};

}
