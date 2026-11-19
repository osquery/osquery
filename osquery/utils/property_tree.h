/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <cstddef>
#include <string>

#include <boost/property_tree/ptree.hpp>

namespace osquery {

/// The deepest nesting readJsonTree and readXmlTree accept.
constexpr std::size_t kPropertyTreeMaxDepth = 128;

/**
 * @brief Parse a JSON document into a property tree, refusing deep nesting.
 *
 * boost::property_tree::read_json recurses once per nested array or object,
 * and the tree it builds is destroyed recursively too, so a document nested
 * deeply enough overflows the stack of the thread parsing it. Use this
 * instead of read_json for documents osquery does not write itself, such as
 * files in users' home directories.
 *
 * @param json The document.
 * @param tree Receives the parsed document, as read_json fills it.
 *
 * @throws boost::property_tree::json_parser_error when read_json would, and
 * when arrays and objects nest deeper than kPropertyTreeMaxDepth.
 */
void readJsonTree(const std::string& json, boost::property_tree::ptree& tree);

/// readJsonTree, into a tree with case-insensitive keys.
void readJsonTree(const std::string& json, boost::property_tree::iptree& tree);

/**
 * @brief Parse an XML document into a property tree, refusing deep nesting.
 *
 * As readJsonTree, for boost::property_tree::read_xml, whose parser
 * recurses once per nested element.
 *
 * @param xml The document.
 * @param tree Receives the parsed document, as read_xml fills it.
 *
 * @throws boost::property_tree::xml_parser_error when read_xml would, and
 * when elements nest deeper than kPropertyTreeMaxDepth.
 */
void readXmlTree(const std::string& xml, boost::property_tree::ptree& tree);

} // namespace osquery
