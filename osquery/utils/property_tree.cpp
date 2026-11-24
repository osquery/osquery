/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <cstring>
#include <sstream>

#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <osquery/utils/property_tree.h>

namespace pt = boost::property_tree;

namespace osquery {

namespace {

/**
 * @brief Whether arrays and objects nest deeper than max_depth.
 *
 * read_json (boost/property_tree/json_parser/detail/parser.hpp) recurses
 * on each bracket outside a string, so this counts those. It needs no
 * other JSON syntax: read_json stops at the first error, and up to there
 * brackets nest as counted here.
 */
bool jsonNestsDeeperThan(const std::string& json, std::size_t max_depth) {
  std::size_t depth = 0;
  bool in_string = false;

  // read_json skips the first three bytes when the first is 0xEF, taking
  // them for a UTF-8 byte order mark without checking the other two.
  std::size_t start = 0;
  if (!json.empty() && static_cast<unsigned char>(json[0]) == 0xEF) {
    start = 3;
  }

  for (std::size_t i = start; i < json.size(); ++i) {
    const char c = json[i];

    if (in_string) {
      if (c == '\\') {
        // Skip the escaped character, which may be a quote.
        ++i;
      } else if (c == '"') {
        in_string = false;
      }

    } else if (c == '"') {
      in_string = true;

    } else if (c == '[' || c == '{') {
      if (++depth > max_depth) {
        return true;
      }

    } else if ((c == ']' || c == '}') && depth > 0) {
      --depth;
    }
  }

  return false;
}

bool isXmlSpace(char c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/// Whether RapidXML reads the character as part of an element name.
bool isXmlNameChar(char c) {
  return c != '\0' && !isXmlSpace(c) && c != '/' && c != '>' && c != '?';
}

/// Whether RapidXML reads the character as part of an attribute name.
bool isXmlAttributeNameChar(char c) {
  return isXmlNameChar(c) && c != '<' && c != '=' && c != '!';
}

void skipXmlSpace(const char*& p) {
  while (isXmlSpace(*p)) {
    ++p;
  }
}

/// Moves p past the next occurrence of end; false if there is none.
bool skipPast(const char*& p, const char* end) {
  p = std::strstr(p, end);
  if (p == nullptr) {
    return false;
  }

  p += std::strlen(end);
  return true;
}

/**
 * @brief Whether elements nest deeper than max_depth.
 *
 * read_xml parses with RapidXML (boost/property_tree/detail/rapidxml.hpp),
 * which recurses into each element's contents. This follows its lexer
 * without building anything: element tags with their quoted attribute
 * values, closing tags, and the comments, CDATA sections, processing
 * instructions and DOCTYPE whose contents it skips. It stops where
 * RapidXML stops, at the first NUL or at markup RapidXML rejects; read_xml
 * then reports the error itself.
 */
bool xmlNestsDeeperThan(const std::string& xml, std::size_t max_depth) {
  const char* p = xml.c_str();
  std::size_t depth = 0;

  while (true) {
    // Text runs up to the next markup.
    while (*p != '\0' && *p != '<') {
      ++p;
    }

    if (*p == '\0') {
      return false;
    }

    ++p;

    if (*p == '/') {
      // A closing tag ends the innermost element.
      if (depth > 0) {
        --depth;
      }

      if (!skipPast(p, ">")) {
        return false;
      }

    } else if (*p == '?') {
      // An XML declaration or a processing instruction.
      ++p;
      if (!skipPast(p, "?>")) {
        return false;
      }

    } else if (std::strncmp(p, "!--", 3) == 0) {
      p += 3;
      if (!skipPast(p, "-->")) {
        return false;
      }

    } else if (std::strncmp(p, "![CDATA[", 8) == 0) {
      p += 8;
      if (!skipPast(p, "]]>")) {
        return false;
      }

    } else if (std::strncmp(p, "!DOCTYPE", 8) == 0 && isXmlSpace(p[8])) {
      // The DOCTYPE ends at the first '>' outside its [] subset.
      p += 9;
      while (*p != '>') {
        if (*p == '\0') {
          return false;
        }

        if (*p != '[') {
          ++p;
          continue;
        }

        ++p;
        for (std::size_t brackets = 1; brackets > 0; ++p) {
          if (*p == '\0') {
            return false;
          } else if (*p == '[') {
            ++brackets;
          } else if (*p == ']') {
            --brackets;
          }
        }
      }

      ++p;

    } else if (*p == '!') {
      // Any other <! markup runs to the next '>'.
      ++p;
      if (!skipPast(p, ">")) {
        return false;
      }

    } else {
      // An element: its name, then its attributes.
      const char* name = p;
      while (isXmlNameChar(*p)) {
        ++p;
      }

      if (p == name) {
        return false;
      }

      skipXmlSpace(p);
      while (isXmlAttributeNameChar(*p)) {
        while (isXmlAttributeNameChar(*p)) {
          ++p;
        }

        skipXmlSpace(p);
        if (*p != '=') {
          return false;
        }

        ++p;
        skipXmlSpace(p);

        // The value runs to the next matching quote.
        const char quote = *p;
        if (quote != '"' && quote != '\'') {
          return false;
        }

        p = std::strchr(p + 1, quote);
        if (p == nullptr) {
          return false;
        }

        ++p;
        skipXmlSpace(p);
      }

      if (p[0] == '/' && p[1] == '>') {
        // An empty element: it has no contents.
        p += 2;

      } else if (*p == '>') {
        ++p;
        if (++depth > max_depth) {
          return true;
        }

      } else {
        return false;
      }
    }
  }
}

template <typename Tree>
void readJsonTreeImpl(const std::string& json, Tree& tree) {
  if (jsonNestsDeeperThan(json, kPropertyTreeMaxDepth)) {
    throw pt::json_parser_error("arrays and objects nested deeper than " +
                                    std::to_string(kPropertyTreeMaxDepth) +
                                    " levels",
                                "",
                                0);
  }

  std::istringstream stream(json);
  pt::read_json(stream, tree);
}

} // namespace

void readJsonTree(const std::string& json, pt::ptree& tree) {
  readJsonTreeImpl(json, tree);
}

void readJsonTree(const std::string& json, pt::iptree& tree) {
  readJsonTreeImpl(json, tree);
}

void readXmlTree(const std::string& xml, pt::ptree& tree) {
  if (xmlNestsDeeperThan(xml, kPropertyTreeMaxDepth)) {
    throw pt::xml_parser_error("elements nested deeper than " +
                                   std::to_string(kPropertyTreeMaxDepth) +
                                   " levels",
                               "",
                               0);
  }

  std::istringstream stream(xml);
  pt::read_xml(stream, tree);
}

} // namespace osquery
