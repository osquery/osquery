// Copyright 2004-present Facebook. All Rights Reserved.

#include <string>
#include <iomanip>

#include <sys/xattr.h>

#include <osquery/logger.h>
#include <osquery/core.h>
#include <osquery/tables.h>
#include <osquery/filesystem.h>
#include <osquery/core/conversions.h>

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

struct XAttrField getFieldLength(int buffer_position,
                                 struct XAttrAttribute x_att_data) {
  struct XAttrField field;
  field.length = 0;
  field.header_length =
      ((unsigned char)x_att_data.attribute_data[buffer_position]) -
      15; // Get the number of bytes
  if (field.header_length > 8) {
    field.header_length = 0;
    return field;
  }

  for (unsigned int i = 1; i < field.header_length + 1; i++) {
    field.length = field.length << 8;
    field.length +=
        (unsigned char)x_att_data.attribute_data[buffer_position + i];
  }
  return field;
}

std::string fixString(const std::string& toFix) {
  std::stringstream result;
  unsigned char byte;
  int count = 0;
  for (int i = 0; i < toFix.length(); ++i) {
    byte = toFix[i];
    if ((int)byte > 0x1F && (int)byte < 0x7F) {
      result << byte;
      continue;
    } else if (byte == 0) {
      result << ' ';
    } else {
      result << '%' << std::setfill('0') << std::setw(2) << std::hex
             << (int)byte;
    }
    count++;
  }
  return result.str();
}

void parseWhereFromData(Row& r, const struct XAttrAttribute x_att) {
  if (x_att.return_value == -1) {
    VLOG(1) << handleError();
  } else {
    r["raw64"] = base64Encode(x_att.attribute_data);
    if (x_att.buffer_length < 11 ||
        0x5F != (unsigned char)x_att.attribute_data[11]) {
      r["download_url"] = "No data";
      r["download_page"] = "No data";
    } else {
      unsigned int starting_position = 12;
      struct XAttrField field = getFieldLength(starting_position, x_att);
      starting_position += 1 + field.header_length;
      if (starting_position + field.length >= x_att.attribute_data.length()) {
        return;
      }
      r["download_url"] = fixString(
          x_att.attribute_data.substr(starting_position, field.length));
      starting_position += field.length + 1;
      if (starting_position + field.length >= x_att.attribute_data.length()) {
        return;
      }
      field = getFieldLength(starting_position, x_att);
      starting_position += field.header_length + 1;
      r["download_page"] = fixString(
          x_att.attribute_data.substr(starting_position, field.length));
    }
  }
}

void getFileData(Row& r,
                 const std::string& path,
                 const std::string& directory) {
  r["path"] = path;
  r["directory"] = directory;
  int ret;
  int buf_len;
  struct XAttrAttribute x_att =
      getAttribute(path, "com.apple.metadata:kMDItemWhereFroms");
  parseWhereFromData(r, x_att);
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
