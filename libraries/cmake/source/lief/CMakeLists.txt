# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
include(ExternalProject)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

function(liefCppMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  #add_library(thirdparty_lief INTERFACE)

  add_library(thirdparty_lief
    "${library_root}/src/Object.cpp"
    "${library_root}/src/Visitor.cpp"
    "${library_root}/src/errors.cpp"
    "${library_root}/src/exception.cpp"
    "${library_root}/src/hash_stream.cpp"
    "${library_root}/src/utils.cpp"
    "${library_root}/src/Object.tcc"
    "${library_root}/src/iostream.cpp"
    "${library_root}/src/logging.cpp"
    "${library_root}/src/Abstract/Binary.cpp"
    "${library_root}/src/Abstract/EnumToString.cpp"
    "${library_root}/src/Abstract/Function.cpp"
    "${library_root}/src/Abstract/Header.cpp"
    "${library_root}/src/Abstract/Parser.cpp"
    "${library_root}/src/Abstract/Relocation.cpp"
    "${library_root}/src/Abstract/Section.cpp"
    "${library_root}/src/Abstract/Symbol.cpp"
    "${library_root}/src/Abstract/hash.cpp"
    #"${library_root}/src/Abstract/json.cpp"
    "${library_root}/src/BinaryStream/BinaryStream.cpp"
    "${library_root}/src/BinaryStream/Convert.cpp"
    "${library_root}/src/BinaryStream/MemoryStream.cpp"
    "${library_root}/src/BinaryStream/VectorStream.cpp"
    "${library_root}/src/visitors/hash.cpp"
    #"${library_root}/src/visitors/json.cpp"
    "${library_root}/src/hash_stream.hpp"
    #"${library_root}/src/frozen.hpp"
    )

  if(DEFINED PLATFORM_MACOS)
    target_sources(thirdparty_lief PRIVATE
      "${library_root}/src/MachO/utils.cpp"
      "${library_root}/src/MachO/Binary.cpp"
      "${library_root}/src/MachO/UUIDCommand.cpp"
      "${library_root}/src/MachO/Symbol.cpp"
      "${library_root}/src/MachO/FatBinary.cpp"
      "${library_root}/src/MachO/EnumToString.cpp"
      "${library_root}/src/MachO/Header.cpp"
      "${library_root}/src/MachO/DynamicSymbolCommand.cpp"
      "${library_root}/src/MachO/Section.cpp"
      "${library_root}/src/MachO/LoadCommand.cpp"
      "${library_root}/src/MachO/BinaryParser.cpp"
      "${library_root}/src/MachO/Builder.cpp"
      "${library_root}/src/MachO/SegmentCommand.cpp"
      "${library_root}/src/MachO/Parser.cpp"
      "${library_root}/src/MachO/SymbolCommand.cpp"
      "${library_root}/src/MachO/MainCommand.cpp"
      "${library_root}/src/MachO/DylibCommand.cpp"
      "${library_root}/src/MachO/DylinkerCommand.cpp"
      "${library_root}/src/MachO/DyldInfo.cpp"
      "${library_root}/src/MachO/Builder.tcc"
      "${library_root}/src/MachO/Binary.tcc"
      "${library_root}/src/MachO/BinaryParser.tcc"
      "${library_root}/src/MachO/FunctionStarts.cpp"
      "${library_root}/src/MachO/SourceVersion.cpp"
      "${library_root}/src/MachO/VersionMin.cpp"
      "${library_root}/src/MachO/Relocation.cpp"
      "${library_root}/src/MachO/RelocationObject.cpp"
      "${library_root}/src/MachO/RelocationDyld.cpp"
      "${library_root}/src/MachO/BindingInfo.cpp"
      "${library_root}/src/MachO/ExportInfo.cpp"
      "${library_root}/src/MachO/ThreadCommand.cpp"
      "${library_root}/src/MachO/RPathCommand.cpp"
      "${library_root}/src/MachO/ParserConfig.cpp"
      "${library_root}/src/MachO/hash.cpp"
      "${library_root}/src/MachO/CodeSignature.cpp"
      "${library_root}/src/MachO/SegmentSplitInfo.cpp"
      "${library_root}/src/MachO/DataInCode.cpp"
      "${library_root}/src/MachO/DataCodeEntry.cpp"
      "${library_root}/src/MachO/SubFramework.cpp"
      "${library_root}/src/MachO/DyldEnvironment.cpp"
      "${library_root}/src/MachO/EncryptionInfo.cpp"
      "${library_root}/src/MachO/TrieNode.cpp"
      "${library_root}/src/MachO/BuildVersion.cpp"
      "${library_root}/src/MachO/TrieNode.hpp"
      )
  endif()

  target_include_directories(thirdparty_lief PRIVATE
    "${library_root}/include"
    "${library_root}/src"
    )
  
  target_include_directories(thirdparty_lief SYSTEM INTERFACE
    "${library_root}/include"
    )

  target_compile_definitions(thirdparty_lief PRIVATE
  CMAKE_BUILD_TYPE=Release
  LIEF_DOC=off
  LIEF_OAT=off
  LIEF_DEX=off
  LIEF_ART=off
  LIEF_VDEX=off
  LIEF_ELF=off
  LIEF_PE=off
  LIEF_LOGGING=off
  LIEF_DEBUG_LOGGING=off
  LIEF_PYTHON_API=off
  LIEF_EXAMPLES=off
  LIEF_DISABLE_FROZEN=on
  CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
  CMAKE_C_COMPILER=${CMAKE_C_COMPILER}
  )

set(LIEF_ELF_SUPPORT 0)
set(LIEF_PE_SUPPORT 0)
set(LIEF_MACHO_SUPPORT 1)

set(LIEF_OAT_SUPPORT 0)
set(LIEF_DEX_SUPPORT 0)
set(LIEF_VDEX_SUPPORT 0)
set(LIEF_ART_SUPPORT 0)

set(LIEF_JSON_SUPPORT 0)
set(LIEF_LOGGING_SUPPORT 0)
set(LIEF_LOGGING_DEBUG_SUPPORT 0)
set(LIEF_FROZEN_ENABLED 0)

configure_file("${library_root}/include/LIEF/config.h.in" "${library_root}/include/LIEF/config.h")

set(MBED_TLS_VERSION 2.25.0)
set(MBED_TLS_SHA256 SHA256=6bf01ef178925f7db3c9027344a50855b116f2defe4a24cbdc0220111a371597)
set(MBED_TLS_URL "${library_root}/third-party/mbedtls-${MBED_TLS_VERSION}.zip" CACHE STRING "URL to MbedTLS")
set(MBED_TLS_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/mbed_tls")

ExternalProject_Add(lief_mbed_tls
  PREFIX            ${MBED_TLS_PREFIX}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  INSTALL_COMMAND   ""
  URL               ${MBED_TLS_URL}
  URL_HASH          ${MBED_TLS_SHA256}
  UPDATE_COMMAND    "" # repetitive update are a pain
  BUILD_BYPRODUCTS  ${MBED_TLS_PREFIX})


ExternalProject_get_property(lief_mbed_tls SOURCE_DIR)
set(MBEDTLS_SOURCE_DIR "${SOURCE_DIR}")
set(MBEDTLS_INCLUDE_DIRS "${MBEDTLS_SOURCE_DIR}/include")

set(mbedtls_src_crypto
  "${MBEDTLS_SOURCE_DIR}/library/aes.c"
  "${MBEDTLS_SOURCE_DIR}/library/aesni.c"
  "${MBEDTLS_SOURCE_DIR}/library/arc4.c"
  "${MBEDTLS_SOURCE_DIR}/library/aria.c"
  "${MBEDTLS_SOURCE_DIR}/library/asn1parse.c"
  "${MBEDTLS_SOURCE_DIR}/library/asn1write.c"
  "${MBEDTLS_SOURCE_DIR}/library/base64.c"
  "${MBEDTLS_SOURCE_DIR}/library/bignum.c"
  "${MBEDTLS_SOURCE_DIR}/library/blowfish.c"
  "${MBEDTLS_SOURCE_DIR}/library/camellia.c"
  "${MBEDTLS_SOURCE_DIR}/library/ccm.c"
  "${MBEDTLS_SOURCE_DIR}/library/chacha20.c"
  "${MBEDTLS_SOURCE_DIR}/library/chachapoly.c"
  "${MBEDTLS_SOURCE_DIR}/library/cipher.c"
  "${MBEDTLS_SOURCE_DIR}/library/cipher_wrap.c"
  "${MBEDTLS_SOURCE_DIR}/library/cmac.c"
  "${MBEDTLS_SOURCE_DIR}/library/ctr_drbg.c"
  "${MBEDTLS_SOURCE_DIR}/library/des.c"
  "${MBEDTLS_SOURCE_DIR}/library/dhm.c"
  "${MBEDTLS_SOURCE_DIR}/library/ecdh.c"
  "${MBEDTLS_SOURCE_DIR}/library/ecdsa.c"
  "${MBEDTLS_SOURCE_DIR}/library/ecjpake.c"
  "${MBEDTLS_SOURCE_DIR}/library/ecp.c"
  "${MBEDTLS_SOURCE_DIR}/library/ecp_curves.c"
  "${MBEDTLS_SOURCE_DIR}/library/entropy.c"
  "${MBEDTLS_SOURCE_DIR}/library/entropy_poll.c"
  "${MBEDTLS_SOURCE_DIR}/library/error.c"
  "${MBEDTLS_SOURCE_DIR}/library/gcm.c"
  "${MBEDTLS_SOURCE_DIR}/library/havege.c"
  "${MBEDTLS_SOURCE_DIR}/library/hkdf.c"
  "${MBEDTLS_SOURCE_DIR}/library/hmac_drbg.c"
  "${MBEDTLS_SOURCE_DIR}/library/md.c"
  "${MBEDTLS_SOURCE_DIR}/library/md2.c"
  "${MBEDTLS_SOURCE_DIR}/library/md4.c"
  "${MBEDTLS_SOURCE_DIR}/library/md5.c"
  "${MBEDTLS_SOURCE_DIR}/library/memory_buffer_alloc.c"
  "${MBEDTLS_SOURCE_DIR}/library/nist_kw.c"
  "${MBEDTLS_SOURCE_DIR}/library/oid.c"
  "${MBEDTLS_SOURCE_DIR}/library/padlock.c"
  "${MBEDTLS_SOURCE_DIR}/library/pem.c"
  "${MBEDTLS_SOURCE_DIR}/library/pk.c"
  "${MBEDTLS_SOURCE_DIR}/library/pk_wrap.c"
  "${MBEDTLS_SOURCE_DIR}/library/pkcs12.c"
  "${MBEDTLS_SOURCE_DIR}/library/pkcs5.c"
  "${MBEDTLS_SOURCE_DIR}/library/pkparse.c"
  "${MBEDTLS_SOURCE_DIR}/library/pkwrite.c"
  "${MBEDTLS_SOURCE_DIR}/library/platform.c"
  "${MBEDTLS_SOURCE_DIR}/library/platform_util.c"
  "${MBEDTLS_SOURCE_DIR}/library/poly1305.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_driver_wrappers.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_se.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_slot_management.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_crypto_storage.c"
  "${MBEDTLS_SOURCE_DIR}/library/psa_its_file.c"
  "${MBEDTLS_SOURCE_DIR}/library/ripemd160.c"
  "${MBEDTLS_SOURCE_DIR}/library/rsa.c"
  "${MBEDTLS_SOURCE_DIR}/library/rsa_internal.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha1.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha256.c"
  "${MBEDTLS_SOURCE_DIR}/library/sha512.c"
  "${MBEDTLS_SOURCE_DIR}/library/threading.c"
  "${MBEDTLS_SOURCE_DIR}/library/timing.c"
  "${MBEDTLS_SOURCE_DIR}/library/version.c"
  "${MBEDTLS_SOURCE_DIR}/library/version_features.c"
  "${MBEDTLS_SOURCE_DIR}/library/xtea.c"
)

set(mbedtls_src_x509
    "${MBEDTLS_SOURCE_DIR}/library/certs.c"
    "${MBEDTLS_SOURCE_DIR}/library/pkcs11.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_create.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crl.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509_csr.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_crt.c"
    "${MBEDTLS_SOURCE_DIR}/library/x509write_csr.c"
)

set(mbedtls_src_tls
  "${MBEDTLS_SOURCE_DIR}/library/debug.c"
  "${MBEDTLS_SOURCE_DIR}/library/net_sockets.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_cache.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_ciphersuites.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_cli.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_cookie.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_msg.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_srv.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_ticket.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_tls.c"
  "${MBEDTLS_SOURCE_DIR}/library/ssl_tls13_keys.c"
)

set_source_files_properties(${mbedtls_src_crypto} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_x509} PROPERTIES GENERATED TRUE)
set_source_files_properties(${mbedtls_src_tls} PROPERTIES GENERATED TRUE)

source_group("mbedtls\\crypto" FILES ${mbedtls_src_crypto})
source_group("mbedtls\\x509" FILES ${mbedtls_src_x509})
source_group("mbedtls\\tls" FILES ${mbedtls_src_tls})

target_sources(thirdparty_lief PRIVATE
  "${mbedtls_src_crypto}"
  "${mbedtls_src_x509}"
  "${mbedtls_src_tls}"
  )

set(SPDLOG_VERSION 1.8.2)
set(SPDLOG_SHA256 SHA256=f0410b12b526065802b40db01304783550d3d20b4b6fe2f8da55f9d08ed2035d)
set(SPDLOG_URL "${library_root}/third-party/spdlog-${SPDLOG_VERSION}.zip" CACHE STRING "URL to the spdlog lib repo")
ExternalProject_Add(lief_spdlog
  URL               ${SPDLOG_URL}
  URL_HASH          ${SPDLOG_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_spdlog SOURCE_DIR)
set(SPDLOG_SOURCE_DIR "${SOURCE_DIR}")
set(SPDLOG_INCLUDE_DIR "${SOURCE_DIR}/include")

set(spdlogging
  "${SPDLOG_SOURCE_DIR}/src/async.cpp"
  "${SPDLOG_SOURCE_DIR}/src/cfg.cpp"
  "${SPDLOG_SOURCE_DIR}/src/color_sinks.cpp"
  "${SPDLOG_SOURCE_DIR}/src/file_sinks.cpp"
  "${SPDLOG_SOURCE_DIR}/src/fmt.cpp"
  "${SPDLOG_SOURCE_DIR}/src/spdlog.cpp"
  "${SPDLOG_SOURCE_DIR}/src/stdout_sinks.cpp"
)
add_dependencies(thirdparty_lief lief_mbed_tls lief_spdlog)
target_link_libraries(thirdparty_lief PRIVATE
  thirdparty_cxx_settings
  )
target_include_directories(thirdparty_lief PRIVATE
  "${MBEDTLS_INCLUDE_DIRS}"
  "${SPDLOG_INCLUDE_DIR}"
  )

set(LIEF_SUPPORT_CXX11 0)
set(LIEF_SUPPORT_CXX14 0)
set(LIEF_SUPPORT_CXX17 0)

if (cxx_std_11 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  set(LIEF_SUPPORT_CXX11 1)
endif()

if (cxx_std_14 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if (${MSVC} AND ${MSVC_TOOLSET_VERSION} GREATER_EQUAL 141)
    set(LIEF_SUPPORT_CXX14 1)
  elseif((NOT DEFINED MSVC) OR (NOT ${MSVC}))
    set(LIEF_SUPPORT_CXX14 1)
  endif()
endif()

if (cxx_std_17 IN_LIST CMAKE_CXX_COMPILE_FEATURES)
  if (${MSVC} AND ${MSVC_TOOLSET_VERSION} GREATER_EQUAL 142)
    set(LIEF_SUPPORT_CXX17 1)
  elseif((NOT DEFINED MSVC) OR (NOT ${MSVC}))
    set(LIEF_SUPPORT_CXX17 1)
  endif()
endif()

configure_file(
  "${library_root}/src/compiler_support.h.in"
  "${library_root}/src/compiler_support.h"
  @ONLY
  )

set_target_properties(
  thirdparty_lief
  PROPERTIES POSITION_INDEPENDENT_CODE ON
             CXX_STANDARD              11
             CXX_STANDARD_REQUIRED     ON
             CXX_VISIBILITY_PRESET     hidden
             C_VISIBILITY_PRESET       hidden)
# cmake-format: on

if(UNIX AND NOT APPLE)
  set_property(
    TARGET thirdparty_lief
    APPEND
    PROPERTY LINK_FLAGS "-Wl,--gc-sections -Wl,--exclude-libs,ALL")
endif()

target_compile_definitions(thirdparty_lief PUBLIC _GLIBCXX_USE_CXX11_ABI=1)

# Enable support for MD2 and MD4 for parsing the Authenticode sigs of older
# executables. Also, some older signed executables use certs with the
# SpcSpAgencyInfo Critical Extension, which mbed TLS doesn't support, so set
# MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION to have it skip this
# extension.
add_definitions(-DMBEDTLS_MD2_C -DMBEDTLS_MD4_C -DMBEDTLS_PEM_PARSE_C
                -DMBEDTLS_X509_CRT_PARSE_C -DMBEDTLS_PEM_WRITE_C
                -DMBEDTLS_PKCS1_V15 -DMBEDTLS_PKCS1_V21
                -DMBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
		)
  macro(ADD_FLAG_IF_SUPPORTED flag name)
  CHECK_C_COMPILER_FLAG("${flag}"   "C_SUPPORTS_${name}")
  CHECK_CXX_COMPILER_FLAG("${flag}" "CXX_SUPPORTS_${name}")

  if (C_SUPPORTS_${name})
    target_compile_options(thirdparty_lief PRIVATE ${flag})
  endif()

  if (CXX_SUPPORTS_${name})
    target_compile_options(thirdparty_lief PRIVATE ${flag})
  endif()
endmacro()

  ADD_FLAG_IF_SUPPORTED("-Wall"                     WALL)
  ADD_FLAG_IF_SUPPORTED("-Wextra"                   WEXTRA)
  ADD_FLAG_IF_SUPPORTED("-Wpedantic"                WPEDANTIC)
  ADD_FLAG_IF_SUPPORTED("-fno-stack-protector"      NO_STACK_PROTECTOR)
  ADD_FLAG_IF_SUPPORTED("-fomit-frame-pointer"      OMIT_FRAME_POINTER)
  ADD_FLAG_IF_SUPPORTED("-fno-strict-aliasing"      NO_STRICT_ALIASING)
  ADD_FLAG_IF_SUPPORTED("-fexceptions"              EXCEPTION)
  ADD_FLAG_IF_SUPPORTED("-fvisibility=hidden"       VISIBILITY)
  ADD_FLAG_IF_SUPPORTED("-Wno-expansion-to-defined" NO_EXPANSION_TO_DEFINED)

  ADD_FLAG_IF_SUPPORTED("-fdiagnostics-color=always" DIAGNOSTICS_COLOR)
  ADD_FLAG_IF_SUPPORTED("-fcolor-diagnostics"        COLOR_DIAGNOSTICS)

endfunction()

liefCppMain()
