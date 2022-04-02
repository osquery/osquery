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

size_t yara_strutils_strlcpy(char* dst, const char* src, size_t size) {
  return yara_strutils::strlcpy(dst, src, size);
}

uint64_t yara_strutils_xtoi(const char* hexstr) {
  return yara_strutils::xtoi(hexstr);
}

int yara_strutils_strnlen_w(const char* w_str) {
  return yara_strutils::strnlen_w(w_str);
}

size_t yara_strutils_strlcpy_w(char* dst, const char* w_src, size_t n) {
  return yara_strutils::strlcpy_w(dst, w_src, n);
}

int yara_strutils_strcmp_w(const char* w_str, const char* str) {
  return yara_strutils::strcmp_w(w_str, str);
}

size_t yara_strutils_strlcat(char* dst, const char* src, size_t size) {
  return yara_strutils::strlcat(dst, src, size);
}

void* yara_strutils_memmem(const void* haystack,
                           size_t haystack_size,
                           const void* needle,
                           size_t needle_size) {
  return yara_strutils::memmem(haystack, haystack_size, needle, needle_size);
}

int yara_strutils_isalnum(const uint8_t* s) {
  return yara_strutils::yr_isalnum(s);
}
}
