// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>
#include <vector>

#include <sys/xattr.h>

#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/logger.h>
#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/core/conversions.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

struct XAttrField {
  uint8_t type;
  uint8_t header_length;
  uint64_t length;
};

struct XAttrAttribute {
  std::string attribute_data;
  int return_value;
  int buffer_length;
};

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

// Broken out into it's own function so we can use it to get attributes later
struct XAttrAttribute getAttribute(const std::string& path,
                                   const std::string attribute) {
  struct XAttrAttribute x_att;
  x_att.buffer_length =
      getxattr(path.c_str(), attribute.c_str(), NULL, 0, 0, 0);
  char* buffer = (char*)malloc(x_att.buffer_length);
  x_att.return_value = getxattr(path.c_str(), attribute.c_str(), buffer,
                                x_att.buffer_length, 0, 0);

  if (x_att.return_value != -1) {
    x_att.attribute_data = std::string(buffer, x_att.buffer_length);
  } else {
    x_att.attribute_data = std::string("");
  }
  free(buffer);
  return x_att;
}

void getFileData(Row& r,
                 const std::string& path,
                 const std::string& directory) {
  struct XAttrAttribute x_att =
      getAttribute(path, "com.apple.metadata:kMDItemWhereFroms");
  r["path"] = path;
  r["directory"] = directory;
  r["raw64"] = base64Encode(x_att.attribute_data);

  pt::ptree data;
  osquery::parsePlistContent(x_att.attribute_data, data);

  if(data.count("root") > 0){
    std::vector<std::string> values;
    for (const auto& node : data.get_child("root")) {
      auto value = node.second.get<std::string>("", "");
      values.push_back(value);
    }
    if(values.size() == 2){
      r["download_url"] = values[0];
      r["download_page"] = values[1];
    }else{
      r["download_url"] = "No data";
      r["download_page"] = "No data";
    }
  }
}

QueryData genXattr(QueryContext& context) {
  QueryData results;
  auto paths = context.constraints["path"].getAll(EQUALS);

  for (const auto& path_string : paths) {
    boost::filesystem::path path = path_string;
    if (!boost::filesystem::is_regular_file(path)) {
      continue;
    }
    Row r;
    getFileData(r, path.string(), path.parent_path().string());
    results.push_back(r);
  }

  auto directories = context.constraints["directory"].getAll(EQUALS);
  for (const auto& directory_string : directories) {
    boost::filesystem::path directory = directory_string;
    if (!boost::filesystem::is_directory(directory)) {
      continue;
    }
    std::vector<std::string> files;
    listFilesInDirectory(directory, files);

    for (auto& file : files) {
      Row r;
      getFileData(r, file, directory.string());
      results.push_back(r);
    }
  }
  return results;
}
}
}
