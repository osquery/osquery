/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/sleuthkit/sleuthkit.h>

#include <iostream>
#include <tsk/libtsk.h>
namespace osquery {

ExpectedImage openLogical(const std::string& device_path,
                          std::shared_ptr<TskImgInfo>& image) {
  std::cout << "open volume" << std::endl;
  auto status = image->open(device_path.c_str(), TSK_IMG_TYPE_DETECT, 0);
  if (status) {
    return ExpectedImage::failure(ConversionError::InvalidArgument,
                                  "Failed to open volume");
  }
  return ExpectedImage::success(status);
}

ExpectedFileContent readRawFile(std::shared_ptr<TskImgInfo>& image,
                                const std::string& file_path,
                                std::vector<char>& file_contents) {
  std::shared_ptr<TskFsInfo> fs(new TskFsInfo());
  // auto* fs = new TskFsInfo();

  TSK_OFF_T offset = 0;
  auto status = fs->open(image.get(), 0, TSK_FS_TYPE_DETECT);
  std::cout << "open fs" << std::endl;
  std::cout << unsigned(status) << std::endl;
  if (status) {
    return ExpectedFileContent::failure(ConversionError::InvalidArgument,
                                        "Failed to open filesystem");
  }
  // std::unique_ptr<TSK_INUM_T> inum(new TSK_INUM_T);
  // std::unique_ptr<TSK_FS_NAME> fs_(new TSK_FS_NAME);

  // std::unique_ptr<TskFsName> fs_name(new TskFsName(fs_.get()));
  // std::cout << "inum made" << std::endl;
  /* status = fs->path2INum(file_path.c_str(), inum.get(), fs_name.get());
  std::cout << unsigned(status) << std::endl;

  if (status || status == -1) {
    return ExpectedFileContent::failure(ConversionError::InvalidArgument,
                                        "Failed to get metadata address");
  }
  */
  std::shared_ptr<TskFsFile> new_file(new TskFsFile());
  // auto* new_file = new TskFsFile();

  std::cout << file_path << std::endl;
  auto result = new_file->open(fs.get(), new_file.get(), file_path.c_str());
  std::cout << unsigned(result) << std::endl;
  if (result) {
    std::cout << "no file info?" << std::endl;
    return ExpectedFileContent::failure(ConversionError::InvalidArgument,
                                        "Failed to get file metadata");
  }

  // auto result = new_file->open(fs.get(), new_file.get(), *inum.get());

  std::cout << "getting meta?" << std::endl;

  std::unique_ptr<TskFsMeta> meta(new_file->getMeta());
  TSK_OFF_T size = meta->getSize();
  auto* buffer = (char*)malloc(size);
  if (buffer != nullptr) {
    ssize_t chunk_size = 0;
    chunk_size =
        new_file->read(0, (char*)&buffer[0], size, TSK_FS_FILE_READ_FLAG_NONE);
    if (chunk_size == -1 || chunk_size != size) {
      std::cout << "hi?" << std::endl;
      // free(buffer);
      return ExpectedFileContent::failure(ConversionError::InvalidArgument,
                                          "Got improper data size");
    }

    std::vector<char> contents(buffer, buffer + size);
    file_contents = contents;
    free(buffer);
  }
  std::cout << file_contents.size() << std::endl;
  return ExpectedFileContent::success(status);
}

} // namespace osquery