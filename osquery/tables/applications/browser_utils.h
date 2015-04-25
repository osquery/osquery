/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

QueryData genChromeBasedExtensions(QueryContext& context,
                                   const fs::path sub_dir);
}
}