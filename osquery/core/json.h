/*
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under the BSD-style license found in the
*  LICENSE file in the root directory of this source tree. An additional grant
*  of patent rights can be found in the PATENTS file in the same directory.
*
*/

#pragma once

#ifdef WIN32
#pragma warning(push, 3)
#pragma warning(disable : 4715)
#endif

#include <boost/property_tree/json_parser.hpp>

#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#ifdef WIN32
#pragma warning(pop)

// We need to reinclude this to re-enable boost's warning suppression
#include <boost/config/compiler/visualc.hpp>
#endif
