/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

// clang-format off
#ifndef STR
#define STR_OF(x) #x
#define STR(x) STR_OF(x)
#endif

#ifdef WIN32
#define STR_EX(...) __VA_ARGS__
#else
#define STR_EX(x) x
#endif
#define CONCAT(x, y) STR(STR_EX(x)STR_EX(y))

#ifdef WIN32
#define USED_SYMBOL
#define EXPORT_FUNCTION __declspec(dllexport)
#else
#define USED_SYMBOL __attribute__((used))
#define EXPORT_FUNCTION
#endif
// clang-format on
