/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/core/conversions.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

// Structure of any OS X extended attribute
struct XAttrAttribute {
  std::string attribute_data;
  int return_value;
  int buffer_length;
};

typedef void (*xattrParseFunction)(QueryData &,
                                   const XAttrAttribute &,
                                   const std::string &,
                                   const std::string &);

// Forward declares of all parse functions
void parseWhereFrom(QueryData &results,
                    const XAttrAttribute &x_att,
                    const std::string &path,
                    const std::string &directory);

void parseQuarantineFile(QueryData &results,
                         const XAttrAttribute &x_att,
                         const std::string &path,
                         const std::string &directory);

// Extended attribute name to the required parse function. If there is no parse
// function, the data is returned as is.
const std::map<std::string, xattrParseFunction> xParseMap = {
    {"com.apple.metadata:kMDItemWhereFroms", parseWhereFrom},
    {"com.apple.quarantine", parseQuarantineFile},
};

// Handle any errors thrown by sys/xattr
std::string handleError() {
  switch (errno) {
  case ENOATTR:
    return "No such attribute";
  case ENOTSUP:
    return "No system support, or support disabled";
  case ERANGE:
    return "Size too small to hold attribute";
  case EPERM:
    return "The named attribute is not permitted for this type of object";
  case EINVAL:
    return "Name is invalid, or options has an unsupported bit set";
  case EISDIR:
    return "The path is not a regular file";
  case ENOTDIR:
    return "Part of the path was not a directory";
  case ENAMETOOLONG:
    return "The filename was too long";
  case EACCES:
    return "Insufficient permissions to read the requested file";
  case ELOOP:
    return "Too many symbolic links were encountered";
  case EFAULT:
    return "The path or name is invalid";
  case EIO:
    return "There was an I/O error while reading";
  default:
    return "No data";
  }
}

// Pull the requested extended attribute from the path and return
// the XAttrAttribute structure
struct XAttrAttribute getAttribute(const std::string &path,
                                   const std::string &attribute) {
  struct XAttrAttribute x_att;
  x_att.buffer_length =
      getxattr(path.c_str(), attribute.c_str(), nullptr, (size_t)0, 0, 0);
  char *buffer = (char *)malloc(x_att.buffer_length);
  x_att.return_value = getxattr(path.c_str(), attribute.c_str(), buffer,
                                x_att.buffer_length, 0, 0);

  if (x_att.return_value != -1) {
    x_att.attribute_data = std::string(buffer, x_att.buffer_length);
  } else {
    x_att.attribute_data = std::string("");
    x_att.buffer_length = 0;
  }
  free(buffer);
  return x_att;
}

// Pull the list of all the extended attributes for a path
std::vector<std::string> parseExtendedAttributeList(const std::string &path) {
  std::vector<std::string> attributes;
  ssize_t value = listxattr(path.c_str(), nullptr, (size_t)0, 0);
  char *content = (char *)malloc(value);
  ssize_t ret = listxattr(path.c_str(), content, value, 0);
  if (ret == 0) {
    return attributes;
  }
  char *stable = content;
  do {
    attributes.push_back(std::string(content));
    content += attributes.back().size() + 1;
  } while (content - stable < value);
  free(stable);
  return attributes;
}

// Parse a given XAttrAttribute struct as a where from plist
void parseWhereFrom(QueryData &results,
                    const XAttrAttribute &x_att,
                    const std::string &path,
                    const std::string &directory) {
  pt::ptree data;
  osquery::parsePlistContent(x_att.attribute_data, data);

  if (data.count("root") > 0) {
    std::vector<std::string> values;
    for (const auto &node : data.get_child("root")) {
      auto value = node.second.get<std::string>("", "");
      values.push_back(value);
    }

    Row r1;
    r1["path"] = path;
    r1["directory"] = directory;
    r1["key"] = "where_from_download_url";
    r1["base64"] = INTEGER(0);

    Row r2;
    r2["path"] = path;
    r2["directory"] = directory;
    r2["key"] = "where_from_download_page";
    r2["base64"] = INTEGER(0);

    if (values.size() == 2) {
      r1["value"] = values[0];
      r2["value"] = values[1];
    } else {
      // Changed to blank because it might not be no data, it might be we just
      // don't know how to parse because it's corrupted.
      r1["value"] = "";
      r2["value"] = "";
    }

    results.push_back(r1);
    results.push_back(r2);
  }
}

// Parse a given XAttrAttribute struct as an OS X quarantine string
void parseQuarantineFile(QueryData &results,
                         const XAttrAttribute &x_att,
                         const std::string &path,
                         const std::string &directory) {
  std::vector<std::string> values = osquery::split(x_att.attribute_data, ";");
  if (values.size() < 2) {
    return;
  }

  Row r1;
  r1["path"] = path;
  r1["directory"] = directory;
  r1["key"] = "quarantine_creator";
  r1["base64"] = INTEGER(0);
  r1["value"] = values[2];

  Row r2;
  r2["path"] = path;
  r2["directory"] = directory;
  r2["key"] = "quarantine_state";
  r2["base64"] = INTEGER(0);
  r2["value"] = values[0];

  results.push_back(r1);
  results.push_back(r2);
}

// Process a file and extract all attribute information, parsed or not.
void getFileData(QueryData &results,
                 const std::string &path,
                 const std::string &directory) {
  std::vector<std::string> attributes = parseExtendedAttributeList(path);
  for (const auto &attribute : attributes) {
    struct XAttrAttribute x_att = getAttribute(path, attribute);
    if (xParseMap.count(attribute) > 0) {
      (*xParseMap.at(attribute))(results, x_att, path, directory);
    } else {
      // We don't have a function in our map for this key so throw it in
      // verbatim
      Row r;
      r["path"] = path;
      r["directory"] = directory;
      r["key"] = attribute;

      if (isPrintable(x_att.attribute_data)) {
        r["base64"] = INTEGER(0);
        r["value"] = x_att.attribute_data;
      } else {
        r["base64"] = INTEGER(1);
        r["value"] = base64Encode(x_att.attribute_data);
      }

      results.push_back(r);
    }
  }
}

QueryData genXattr(QueryContext &context) {
  QueryData results;
  auto paths = context.constraints["path"].getAll(EQUALS);

  for (const auto &path_string : paths) {
    boost::filesystem::path path = path_string;
    // Folders can have extended attributes too
    if (!(boost::filesystem::is_regular_file(path) ||
          boost::filesystem::is_directory(path))) {
      continue;
    }
    getFileData(results, path.string(), path.parent_path().string());
  }

  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto &directory : directories) {
    if (!boost::filesystem::is_directory(directory)) {
      continue;
    }
    std::vector<std::string> files;
    listFilesInDirectory(directory, files);

    for (auto &file : files) {
      getFileData(results, file, directory);
    }
  }
  return results;
}
}
}
