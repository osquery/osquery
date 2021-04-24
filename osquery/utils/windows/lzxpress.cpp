/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/windows/lzxpress.h>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string.hpp>

#include <algorithm>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <windows.h>
#include <winternl.h>

namespace osquery {
std::string decompressLZxpress(std::vector<char> prefetch_data,
                               unsigned long size) {
  static HMODULE hDLL =
      LoadLibraryExW(L"ntdll.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
  if (hDLL == nullptr) {
    LOG(ERROR) << "Failed to load ntdll.dll";
    return "Error";
  }

  typedef HRESULT(WINAPI * pRtlDecompressBufferEx)(
      _In_ unsigned int16 format,
      _Out_ unsigned char* uncompressedBuffer,
      _In_ unsigned long uncompressedSize,
      _In_ unsigned char* data,
      _In_ unsigned long dataSize,
      _Out_ unsigned long* finalSize,
      _In_ PVOID workspace);

  typedef HRESULT(WINAPI * pRtlGetCompressionWorkSpaceSize)(
      _In_ unsigned short format,
      _Out_ unsigned long* bufferWorkSpaceSize,
      _Out_ unsigned long* fragmentWorkSpaceSize);

  pRtlDecompressBufferEx RtlDecompressBufferEx;
  pRtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize;
  RtlGetCompressionWorkSpaceSize =
      (pRtlGetCompressionWorkSpaceSize)GetProcAddress(
          hDLL, "RtlGetCompressionWorkSpaceSize");
  if (RtlGetCompressionWorkSpaceSize == nullptr) {
    LOG(ERROR) << "Failed to load function RtlGetCompressionWorkSpaceSize";
    return "Error";
  }
  RtlDecompressBufferEx =
      (pRtlDecompressBufferEx)GetProcAddress(hDLL, "RtlDecompressBufferEx");

  if (RtlDecompressBufferEx == nullptr) {
    LOG(ERROR) << "Failed to load function RtlDecompressBufferEx";
    return "Error";
  }
  unsigned long bufferWorkSpaceSize = 0ul;
  unsigned long fragmentWorkSpaceSize = 0ul;
  auto results = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF,
                                                &bufferWorkSpaceSize,
                                                &fragmentWorkSpaceSize);
  if (results != 0) {
    LOG(ERROR) << "Failed to set compression workspace size";
    return "Error";
  }
  unsigned char* compressed_data = new unsigned char[prefetch_data.size() - 8];

  // Substract header size from compressed data size
  for (int i = 8; i < prefetch_data.size(); i++) {
    compressed_data[i - 8] = prefetch_data[i];
  }
  unsigned char* output_buffer = new unsigned char[size];

  unsigned long buffer_size =
      static_cast<unsigned long>(prefetch_data.size() - 8);
  unsigned long final_size = 0ul;
  PVOID fragment_workspace = new unsigned char*[fragmentWorkSpaceSize];
  auto decom_results = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF,
                                             output_buffer,
                                             size,
                                             compressed_data,
                                             buffer_size,
                                             &final_size,
                                             fragment_workspace);
  if (decom_results != 0) {
    LOG(ERROR) << "Failed to decompress data";
    return "Error";
  }
  std::stringstream ss;
  for (unsigned long i = 0; i < size; i++) {
    std::stringstream value;
    value << std::setfill('0') << std::setw(2);
    value << std::hex << std::uppercase << (int)(output_buffer[i]);
    ss << value.str();
  }
  std::string decompress_hex = ss.str();
  return decompress_hex;
}

} // namespace osquery
