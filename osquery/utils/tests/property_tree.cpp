/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/utils/property_tree.h>

namespace pt = boost::property_tree;

namespace osquery {

namespace {

/// Deep enough to overflow the stack of read_json and read_xml.
const std::size_t kStackOverflowDepth = 1000000;

std::string repeat(const std::string& text, std::size_t count) {
  std::string output;
  output.reserve(text.size() * count);
  for (std::size_t i = 0; i < count; ++i) {
    output += text;
  }

  return output;
}

std::string nestedJsonArrays(std::size_t depth) {
  return repeat("[", depth) + repeat("]", depth);
}

std::string nestedJsonObjects(std::size_t depth) {
  return repeat("{\"a\":", depth - 1) + "{}" + repeat("}", depth - 1);
}

std::string nestedXml(std::size_t depth) {
  return repeat("<a>", depth) + repeat("</a>", depth);
}

} // namespace

class PropertyTreeTests : public testing::Test {};

TEST_F(PropertyTreeTests, test_read_json_tree) {
  pt::ptree tree;
  readJsonTree(R"({"name": "osquery", "list": [1, {"a": true}],
                   "nested": {"key": "value"}})",
               tree);
  EXPECT_EQ(tree.get<std::string>("name"), "osquery");
  EXPECT_EQ(tree.get_child("list").size(), 2U);
  EXPECT_EQ(tree.get<std::string>("nested.key"), "value");

  pt::iptree itree;
  readJsonTree(R"({"Name": "osquery"})", itree);
  EXPECT_EQ(itree.get<std::string>("name"), "osquery");

  EXPECT_THROW(readJsonTree(R"({"name": )", tree), pt::json_parser_error);
}

TEST_F(PropertyTreeTests, test_read_json_tree_max_depth) {
  pt::ptree tree;
  EXPECT_NO_THROW(readJsonTree(nestedJsonArrays(kPropertyTreeMaxDepth), tree));
  EXPECT_THROW(readJsonTree(nestedJsonArrays(kPropertyTreeMaxDepth + 1), tree),
               pt::json_parser_error);

  EXPECT_NO_THROW(readJsonTree(nestedJsonObjects(kPropertyTreeMaxDepth), tree));
  EXPECT_THROW(readJsonTree(nestedJsonObjects(kPropertyTreeMaxDepth + 1), tree),
               pt::json_parser_error);

  // Brackets inside strings, escaped quotes included, are not nesting.
  const auto brackets = repeat("[{", kPropertyTreeMaxDepth);
  EXPECT_NO_THROW(readJsonTree(
      "{\"" + brackets + "\\\"" + brackets + "\": \"" + brackets + "\"}",
      tree));

  // Neither are siblings.
  EXPECT_NO_THROW(
      readJsonTree("[" + repeat("[[]],", kPropertyTreeMaxDepth) + "{}]", tree));

  // A string ending in an escaped backslash ends at the next quote.
  EXPECT_NO_THROW(readJsonTree(
      R"(["\\", )" + nestedJsonArrays(kPropertyTreeMaxDepth - 1) + "]", tree));
  EXPECT_THROW(
      readJsonTree(R"(["\\", )" + nestedJsonArrays(kPropertyTreeMaxDepth) + "]",
                   tree),
      pt::json_parser_error);

  // read_json skips three bytes after a leading 0xEF, as a byte order mark.
  readJsonTree("\xEF\xBB\xBF{\"name\": \"osquery\"}", tree);
  EXPECT_EQ(tree.get<std::string>("name"), "osquery");
  EXPECT_NO_THROW(
      readJsonTree("\xEF[[" + nestedJsonArrays(kPropertyTreeMaxDepth), tree));
}

TEST_F(PropertyTreeTests, test_read_json_tree_deeply_nested) {
  pt::ptree tree;
  EXPECT_THROW(readJsonTree(nestedJsonArrays(kStackOverflowDepth), tree),
               pt::json_parser_error);

  pt::iptree itree;
  EXPECT_THROW(readJsonTree(nestedJsonArrays(kStackOverflowDepth), itree),
               pt::json_parser_error);

  // Not hidden behind what read_json takes for a byte order mark.
  EXPECT_THROW(
      readJsonTree("\xEF\"x" + nestedJsonArrays(kStackOverflowDepth), tree),
      pt::json_parser_error);
}

TEST_F(PropertyTreeTests, test_read_xml_tree) {
  pt::ptree tree;
  readXmlTree(R"(<?xml version="1.0"?>
                 <component type="desktop">
                   <id>org.osquery.osquery</id>
                   <name>osquery</name>
                 </component>)",
              tree);
  EXPECT_EQ(tree.get<std::string>("component.<xmlattr>.type"), "desktop");
  EXPECT_EQ(tree.get<std::string>("component.name"), "osquery");

  EXPECT_THROW(readXmlTree("<component>", tree), pt::xml_parser_error);
}

TEST_F(PropertyTreeTests, test_read_xml_tree_max_depth) {
  pt::ptree tree;
  EXPECT_NO_THROW(readXmlTree(nestedXml(kPropertyTreeMaxDepth), tree));
  EXPECT_THROW(readXmlTree(nestedXml(kPropertyTreeMaxDepth + 1), tree),
               pt::xml_parser_error);

  // Tags inside markup whose contents read_xml skips are not nesting,
  // empty elements have no contents, and siblings are not nesting.
  const auto tags = repeat("<a>", kPropertyTreeMaxDepth + 1);
  const auto xml = "<?xml version=\"1.0\"?><!DOCTYPE root [<!-- [] -->" + tags +
                   "]><root first=\"" + tags + "\" second='" + tags + "'><!--" +
                   tags + "--><![CDATA[" + tags + "]]><?pi " + tags + "?>" +
                   repeat("<a/><a></a>", 2) +
                   repeat("<a />", kPropertyTreeMaxDepth + 1) + "</root>";
  EXPECT_NO_THROW(readXmlTree(xml, tree));
  EXPECT_EQ(tree.get_child("root").count("a"), kPropertyTreeMaxDepth + 5);
}

TEST_F(PropertyTreeTests, test_read_xml_tree_deeply_nested) {
  pt::ptree tree;
  EXPECT_THROW(readXmlTree(nestedXml(kStackOverflowDepth), tree),
               pt::xml_parser_error);
}

} // namespace osquery
