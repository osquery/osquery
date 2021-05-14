/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/logger/logger.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/windows/lzxpress.h>

namespace osquery {
ExpectedDecompressData decompressLZxpress(std::vector<char> prefetch_data,
                                          unsigned long size) {
  typedef HRESULT(WINAPI * pRtlDecompressBufferEx)(
      _In_ USHORT format,
      _Out_ PUCHAR uncompressedBuffer,
      _In_ ULONG uncompressedSize,
      _In_ PUCHAR data,
      _In_ ULONG dataSize,
      _Out_ PULONG finalSize,
      _In_ PVOID workspace);

  typedef HRESULT(WINAPI * pRtlGetCompressionWorkSpaceSize)(
      _In_ USHORT format,
      _Out_ PULONG bufferWorkSpaceSize,
      _Out_ PULONG fragmentWorkSpaceSize);

  pRtlDecompressBufferEx RtlDecompressBufferEx;
  pRtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize;
  RtlGetCompressionWorkSpaceSize =
      reinterpret_cast<pRtlGetCompressionWorkSpaceSize>(GetProcAddress(
          GetModuleHandleA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize"));
  if (RtlGetCompressionWorkSpaceSize == nullptr) {
    LOG(ERROR) << "Failed to load function RtlGetCompressionWorkSpaceSize";
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to load function RtlGetCompressionWorkSpaceSize");
  }
  RtlDecompressBufferEx = reinterpret_cast<pRtlDecompressBufferEx>(
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBufferEx"));

  // Check for decompression function, only exists on Win8+
  if (RtlDecompressBufferEx == nullptr) {
    LOG(ERROR) << "Failed to load function RtlDecompressBufferEx";
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to load function RtlDecompressBufferEx");
  }
  ULONG bufferWorkSpaceSize = 0ul;
  ULONG fragmentWorkSpaceSize = 0ul;
  auto results = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF,
                                                &bufferWorkSpaceSize,
                                                &fragmentWorkSpaceSize);
  if (results != 0) {
    LOG(ERROR) << "Failed to set compression workspace size";
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to set compression workspace size");
  }
  std::vector<UCHAR> compressed_data;
  compressed_data.resize(prefetch_data.size() - 8);

  // Substract header size from compressed data size
  for (int i = 8; i < prefetch_data.size(); i++) {
    compressed_data[i - 8] = prefetch_data[i];
  }
  std::vector<UCHAR> output_buffer;
  output_buffer.resize(size);

  ULONG buffer_size = static_cast<ULONG>(prefetch_data.size() - 8);
  ULONG final_size = 0ul;
  std::vector<PVOID> fragment_workspace;
  fragment_workspace.resize(fragmentWorkSpaceSize);
  auto decom_results = RtlDecompressBufferEx(COMPRESSION_FORMAT_XPRESS_HUFF,
                                             output_buffer.data(),
                                             size,
                                             compressed_data.data(),
                                             buffer_size,
                                             &final_size,
                                             fragment_workspace.data());
  if (decom_results != 0) {
    LOG(ERROR) << "Failed to decompress data";
    return ExpectedDecompressData::failure(ConversionError::InvalidArgument,
                                           "Failed to decompress data");
  }
  return ExpectedDecompressData::success(output_buffer);
}
} // namespace osquery
