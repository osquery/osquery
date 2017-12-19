/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/property_tree/ptree.hpp>

#include <osquery/tables.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

/**
 * @brief Utility method to check if specified string is SHA-256 hash or a
 * substring.
 */
bool checkStringIsHash(const std::string& str);

/**
* @brief Makes API calls to the docker UNIX socket.
*
* @param uri Relative URI to invoke GET HTTP method.
* @param tree Property tree where JSON result is stored.
* @return Status with 0 code on success. Non-negative status with error
*         message.
*/
Status dockerApi(const std::string& uri, pt::ptree& tree);

}
}
