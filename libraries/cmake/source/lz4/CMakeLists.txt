# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

# rdkafka currently embeds a copy of LZ4 sources, but rdkafka doesn't have a CPE
# to search for CVEs.
# For this reason and because we normally prefer to build all the needed libraries
# separately, we brought out LZ4, so that we can track its CVEs and update it independently.
# One problem with this though is that LZ4 depends on xxhash and rdkafka uses
# a slightly modified version of xxhash APIs.
# We therefore have to build a copy of LZ4 for each user, and we have to namespace the APIs
# for each dependee (rdkafka currently), so that they also refer to the specific namespaced version
# of the xxhash APIs.

# This helper function preprends a namespace to the exported LZ4 frame APIs,
# which are the ones that depend on xxhash.
# It should be accessible to all the other libraries,
# since we have put the lz4 library as the first processed one in the main CMakeLists.txt.
function(renameLZ4APIs namespace output_var)

  # NOTE: This list has to be manually kept up to date
  list(APPEND lz4_frame_apis
    "LZ4F_isError"
    "LZ4F_getErrorName"
    "LZ4F_compressionLevel_max"
    "LZ4F_compressFrameBound"
    "LZ4F_compressFrame"
    "LZ4F_getVersion"
    "LZ4F_createCompressionContext"
    "LZ4F_freeCompressionContext"
    "LZ4F_compressBegin"
    "LZ4F_compressBound"
    "LZ4F_compressUpdate"
    "LZ4F_flush"
    "LZ4F_compressEnd"
    "LZ4F_createDecompressionContext"
    "LZ4F_freeDecompressionContext"
    "LZ4F_headerSize"
    "LZ4F_getFrameInfo"
    "LZ4F_decompress"
    "LZ4F_resetDecompressionContext"
    "LZ4F_getErrorCode"
    "LZ4F_getBlockSize"
    "LZ4F_uncompressedUpdate"
    "LZ4F_createCDict"
    "LZ4F_freeCDict"
    "LZ4F_compressFrame_usingCDict"
    "LZ4F_compressBegin_usingCDict"
    "LZ4F_decompress_usingDict"
    "LZ4F_decompress_usingDict"
    "LZ4F_createCompressionContext_advanced"
    "LZ4F_createDecompressionContext_advanced"
    "LZ4F_createCDict_advanced"
  )

  foreach(api ${lz4_frame_apis})
    list(APPEND ${output_var} ${api}=${namespace}_${api})
  endforeach()

  set(${output_var} "${${output_var}}" PARENT_SCOPE)
endfunction()

function(lz4Main)

set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

add_library(thirdparty_lz4
  "${library_root}/lib/lz4.c"
  "${library_root}/lib/lz4hc.c"
  "${library_root}/lib/lz4.h"
  "${library_root}/lib/lz4hc.h"
)

add_library(thirdparty_lz4_frame INTERFACE)
target_sources(thirdparty_lz4_frame INTERFACE
  "${library_root}/lib/lz4frame.c"
  "${library_root}/lib/lz4frame.h"
)

target_link_libraries(thirdparty_lz4_frame INTERFACE
  thirdparty_lz4
)

target_link_libraries(thirdparty_lz4
  PRIVATE
    thirdparty_c_settings
)

endfunction()

lz4Main()
