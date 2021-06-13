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
    "${library_root}/src/BinaryStream/BinaryStream.cpp"
    "${library_root}/src/BinaryStream/Convert.cpp"
    "${library_root}/src/BinaryStream/MemoryStream.cpp"
    "${library_root}/src/BinaryStream/VectorStream.cpp"
    "${library_root}/src/visitors/hash.cpp"
    "${library_root}/src/hash_stream.hpp"
    )

  if(DEFINED PLATFORM_MACOS)
    set(LIEF_MACHO_SUPPORT 1)
    file(READ "${library_root}/include/LIEF/MachO/enums.inc"      LIEF_MACHO_ENUMS)
    file(READ "${library_root}/include/LIEF/MachO/structures.inc" LIEF_MACHO_STRUCTURES)
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
  if(DEFINED PLATFORM_WINDOWS)
    set(LIEF_PE_SUPPORT 1)
    file(READ "${library_root}/include/LIEF/PE/enums.inc"      LIEF_PE_ENUMS)
    file(READ "${library_root}/include/LIEF/PE/structures.inc" LIEF_PE_STRUCTURES)
    target_sources(thirdparty_lief PRIVATE
       "${library_root}/src/PE/utils.cpp"
  "${library_root}/src/PE/ExportEntry.cpp"
  "${library_root}/src/PE/Binary.cpp"
  "${library_root}/src/PE/Symbol.cpp"
  "${library_root}/src/PE/EnumToString.cpp"
  "${library_root}/src/PE/Header.cpp"
  "${library_root}/src/PE/DosHeader.cpp"
  "${library_root}/src/PE/RichHeader.cpp"
  "${library_root}/src/PE/RichEntry.cpp"
  "${library_root}/src/PE/ResourceDirectory.cpp"
  "${library_root}/src/PE/Import.cpp"
  "${library_root}/src/PE/ResourceNode.cpp"
  "${library_root}/src/PE/Export.cpp"
  "${library_root}/src/PE/Section.cpp"
  "${library_root}/src/PE/OptionalHeader.cpp"
  "${library_root}/src/PE/Builder.cpp"
  "${library_root}/src/PE/Parser.cpp"
  "${library_root}/src/PE/ResourcesManager.cpp"
  "${library_root}/src/PE/Relocation.cpp"
  "${library_root}/src/PE/TLS.cpp"
  "${library_root}/src/PE/Debug.cpp"
  "${library_root}/src/PE/CodeView.cpp"
  "${library_root}/src/PE/CodeViewPDB.cpp"
  "${library_root}/src/PE/Pogo.cpp"
  "${library_root}/src/PE/PogoEntry.cpp"
  "${library_root}/src/PE/ImportEntry.cpp"
  "${library_root}/src/PE/ResourceData.cpp"
  "${library_root}/src/PE/RelocationEntry.cpp"
  "${library_root}/src/PE/DataDirectory.cpp"
  "${library_root}/src/PE/CodeIntegrity.cpp"
  "${library_root}/src/PE/Builder.tcc"
  "${library_root}/src/PE/Parser.tcc"
  "${library_root}/src/PE/resources/ResourceVersion.cpp"
  "${library_root}/src/PE/resources/ResourceDialog.cpp"
  "${library_root}/src/PE/resources/ResourceDialogItem.cpp"
  "${library_root}/src/PE/resources/ResourceVersion.cpp"
  "${library_root}/src/PE/resources/ResourceFixedFileInfo.cpp"
  "${library_root}/src/PE/resources/ResourceVarFileInfo.cpp"
  "${library_root}/src/PE/resources/ResourceStringFileInfo.cpp"
  "${library_root}/src/PE/resources/LangCodeItem.cpp"
  "${library_root}/src/PE/resources/ResourceIcon.cpp"
  "${library_root}/src/PE/resources/ResourceStringTable.cpp"
  "${library_root}/src/PE/resources/ResourceAccelerator.cpp"
    "${library_root}/src/PE/LoadConfigurations/LoadConfigurations.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfiguration.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfiguration.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV0.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV0.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV1.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV1.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV2.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV2.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV3.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV3.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV4.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV4.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV5.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV5.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV6.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV6.tcc"

  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV7.cpp"
  "${library_root}/src/PE/LoadConfigurations/LoadConfigurationV7.tcc"
    "${library_root}/src/PE/signatures/Attribute.cpp"
  "${library_root}/src/PE/signatures/ContentInfo.cpp"
  "${library_root}/src/PE/signatures/Signature.cpp"
  "${library_root}/src/PE/signatures/SignerInfo.cpp"
  "${library_root}/src/PE/signatures/x509.cpp"
  "${library_root}/src/PE/signatures/OIDToString.cpp"
  "${library_root}/src/PE/signatures/SignatureParser.cpp"
  "${library_root}/src/PE/signatures/RsaInfo.cpp"
    "${library_root}/src/PE/signatures/attributes/GenericType.cpp"
  "${library_root}/src/PE/signatures/attributes/ContentType.cpp"

  "${library_root}/src/PE/signatures/attributes/SpcSpOpusInfo.cpp"

  "${library_root}/src/PE/signatures/attributes/MsCounterSign.cpp"
  "${library_root}/src/PE/signatures/attributes/MsSpcNestedSignature.cpp"
  "${library_root}/src/PE/signatures/attributes/MsSpcStatementType.cpp"

  "${library_root}/src/PE/signatures/attributes/PKCS9AtSequenceNumber.cpp"
  "${library_root}/src/PE/signatures/attributes/PKCS9CounterSignature.cpp"
  "${library_root}/src/PE/signatures/attributes/PKCS9MessageDigest.cpp"
  "${library_root}/src/PE/signatures/attributes/PKCS9SigningTime.cpp"
  )
  target_include_directories(thirdpart_lief PRIVATE
    "${library_root}/src/PE/utils/ordinals_lookup_tables"
    "${library_root}/src/PE/utils/ordinals_lookup_tables_std"
    "${library_root}/src/PE/signatures/"
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

set(LIEF_OAT_SUPPORT 0)
set(LIEF_DEX_SUPPORT 0)
set(LIEF_VDEX_SUPPORT 0)
set(LIEF_ART_SUPPORT 0)

set(LIEF_JSON_SUPPORT 0)
set(LIEF_LOGGING_SUPPORT 0)
set(LIEF_LOGGING_DEBUG_SUPPORT 0)
set(LIEF_FROZEN_ENABLED 0)

configure_file("${library_root}/include/LIEF/config.h.in" "${library_root}/include/LIEF/config.h")
configure_file("${library_root}/include/LIEF/MACHO/enums.hpp.in" "${library_root}/include/LIEF/MACHO/enums.hpp")
configure_file("${library_root}/include/LIEF/MACHO/Structures.hpp.in" "${library_root}/include/LIEF/MACHO/Structures.hpp")
configure_file(
  "${library_root}/include/LIEF/PE/enums.hpp.in"
  "${library_root}/include/LIEF/PE/enums.hpp"
  @ONLY
)

configure_file(
  "${library_root}/include/LIEF/PE/Structures.hpp.in"
  "${library_root}/include/LIEF/PE/Structures.hpp"
  @ONLY
)

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

set(LEAF_VERSION 0.3.1) # Custom fix to remove use of SUBLANG_DEFAULT in common.hpp and all.hpp
set(LEAF_SHA256 SHA256=b925413d165cb841e560e44438dc6ad6bfcbf537d526a51489d518ad381a4c11  )
set(LEAF_URL "${library_root}/third-party/leaf-${LEAF_VERSION}.zip" CACHE STRING "URL to Leaf")
ExternalProject_Add(lief_leaf # :)
  URL               ${LEAF_URL}
  URL_HASH          ${LEAF_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_leaf SOURCE_DIR)
set(LEAF_INCLUDE_DIR "${SOURCE_DIR}/include")

set(UTFCPP_VERSION 3.1.2) # Custom fix to remove use of SUBLANG_DEFAULT in common.hpp and all.hpp
set(UTFCPP_SHA256 SHA256=b77bff122a6d4f2a7a1ab409086bbb59bf899a2fdde12e1a85a4305fa91764c4)
set(UTFCPP_URL "${library_root}/third-party/utfcpp-${UTFCPP_VERSION}.zip" CACHE STRING "URL to UTFCPP")
ExternalProject_Add(lief_utfcpp
  URL               ${UTFCPP_URL}
  URL_HASH          ${UTFCPP_SHA256}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND     ""
  UPDATE_COMMAND    ""
  INSTALL_COMMAND   "")

ExternalProject_get_property(lief_utfcpp SOURCE_DIR)
set(UTFCPP_INCLUDE_DIR "${SOURCE_DIR}/source")



add_dependencies(thirdparty_lief lief_mbed_tls lief_spdlog lief_leaf lief_utfcpp)
target_link_libraries(thirdparty_lief PRIVATE
  thirdparty_cxx_settings
  thirdparty_c_settings
  )
target_link_libraries(thirdparty_lief PUBLIC
  thirdparty_mbedtls
  )

# =======================================
# Leaf
# =======================================
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/boost/leaf/all.hpp
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${LEAF_INCLUDE_DIR}/
    ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/
  DEPENDS lief_leaf)

target_sources(thirdparty_lief PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/boost/leaf/all.hpp)

add_custom_command(OUTPUT ${library_root}/include/LIEF/third-party/boost/leaf/all.hpp
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${LEAF_INCLUDE_DIR}/
    ${library_root}/include/LIEF/third-party/
  DEPENDS lief_leaf)

target_sources(thirdparty_lief PRIVATE
  ${library_root}/include/LIEF/third-party/boost/leaf/all.hpp)

# =======================================
# utfcpp
# =======================================
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/utfcpp/utf8.h
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${UTFCPP_INCLUDE_DIR}/
    ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/utfcpp
  DEPENDS lief_utfcpp)

target_sources(thirdparty_lief PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}/include/LIEF/third-party/utfcpp/utf8.h)

add_custom_command(OUTPUT ${library_root}/include/LIEF/third-party/utfcpp/utf8.h
  COMMAND
    ${CMAKE_COMMAND} -E copy_directory ${UTFCPP_INCLUDE_DIR}/
    ${library_root}/include/LIEF/third-party/utfcpp
  DEPENDS lief_utfcpp)

target_sources(thirdparty_lief PRIVATE
  ${library_root}/include/LIEF/third-party/utfcpp/utf8.h)

target_include_directories(thirdparty_lief PRIVATE
  "${MBEDTLS_INCLUDE_DIRS}"
  "${SPDLOG_INCLUDE_DIR}"
  "${LEAF_INCLUDE_DIR}/boost/leaf"
  "${UTFCPP_INCLUDE_DIR}"
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
endfunction()

liefCppMain()
