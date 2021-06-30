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

#include <winternl.h>

namespace osquery {
namespace {

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif

typedef NTSTATUS(WINAPI* RTLDECOMPRESSBUFFEREX)(_In_ USHORT format,
                                                _Out_ PUCHAR uncompressedBuffer,
                                                _In_ ULONG uncompressedSize,
                                                _In_ PUCHAR data,
                                                _In_ ULONG dataSize,
                                                _Out_ PULONG finalSize,
                                                _In_ PVOID workspace);

typedef NTSTATUS(WINAPI* RTLGETCOMPRESSIONWORKSPACESIZE)(
    _In_ USHORT format,
    _Out_ PULONG bufferWorkSpaceSize,
    _Out_ PULONG fragmentWorkSpaceSize);

} // namespace

ExpectedDecompressData decompressLZxpress(std::vector<UCHAR>& prefetch_data,
                                          unsigned long size) {
  RTLGETCOMPRESSIONWORKSPACESIZE RtlGetCompressionWorkSpaceSize;
  RTLDECOMPRESSBUFFEREX RtlDecompressBufferEx;

  RtlGetCompressionWorkSpaceSize =
      reinterpret_cast<RTLGETCOMPRESSIONWORKSPACESIZE>(GetProcAddress(
          GetModuleHandleA("ntdll.dll"), "RtlGetCompressionWorkSpaceSize"));
  if (RtlGetCompressionWorkSpaceSize == nullptr) {
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to load function RtlGetCompressionWorkSpaceSize");
  }

  RtlDecompressBufferEx = reinterpret_cast<RTLDECOMPRESSBUFFEREX>(
      GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDecompressBufferEx"));
  // Check for decompression function, only exists on Win8+
  if (RtlDecompressBufferEx == nullptr) {
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to load function RtlDecompressBufferEx");
  }

  ULONG bufferWorkSpaceSize = 0ul;
  ULONG fragmentWorkSpaceSize = 0ul;
  auto results = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_XPRESS_HUFF,
                                                &bufferWorkSpaceSize,
                                                &fragmentWorkSpaceSize);
  if (results != STATUS_SUCCESS) {
    return ExpectedDecompressData::failure(
        ConversionError::InvalidArgument,
        "Failed to set compression workspace size");
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
                                             &prefetch_data[8],
                                             buffer_size,
                                             &final_size,
                                             fragment_workspace.data());
  if (decom_results != STATUS_SUCCESS) {
    return ExpectedDecompressData::failure(ConversionError::InvalidArgument,
                                           "Failed to decompress data");
  }
  return ExpectedDecompressData::success(output_buffer);
}
} // namespace osquery
