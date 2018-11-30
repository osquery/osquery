# Copyright (c) 2018-present, Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.13.1)

function(osqueryThirdpartyMain)
  initializePythonPathFolder()

  add_subdirectory("augeas")
  add_subdirectory("aws-sdk-cpp")
  add_subdirectory("berkeley-db")
  add_subdirectory("boost")
  add_subdirectory("bzip2")
  add_subdirectory("gflags")
  add_subdirectory("glog")
  add_subdirectory("googletest")
  add_subdirectory("jinja2")
  add_subdirectory("libarchive")
  add_subdirectory("libaudit")
  add_subdirectory("libcryptsetup")
  add_subdirectory("libdevmapper")
  add_subdirectory("libdpkg")
  add_subdirectory("libelfin")
  add_subdirectory("libgcrypt")
  add_subdirectory("libgpg-error")
  add_subdirectory("libiptables")
  add_subdirectory("libmagic")
  add_subdirectory("librdkafka")
  add_subdirectory("libresolv")
  add_subdirectory("librpm")
  add_subdirectory("libudev")
  add_subdirectory("libxml2")
  add_subdirectory("linenoise-ng")
  add_subdirectory("lldpd")
  add_subdirectory("lzma")
  add_subdirectory("markupsafe")
  add_subdirectory("openssl")
  add_subdirectory("popt")
  add_subdirectory("pthread")
  add_subdirectory("rapidjson")
  add_subdirectory("rocksdb")
  add_subdirectory("sleuthkit")
  add_subdirectory("smartmontools")
  add_subdirectory("sqlite")
  add_subdirectory("ssdeep-cpp")
  add_subdirectory("thrift")
  add_subdirectory("util-linux")
  add_subdirectory("yara")
  add_subdirectory("zlib")
  add_subdirectory("zstd")
endfunction()

# Generates a target named identifier_downloader that will acquire the remote file while also verifying
# its hash
function(downloadRemoteFile identifier base_url file_name hash)
  set(destination "${CMAKE_CURRENT_BINARY_DIR}/${file_name}")
  set(url "${base_url}/${file_name}")

  if(DEFINED PLATFORM_WINDOWS)
    set(command_prefix "python2")
  elseif(DEFINED PLATFORM_MACOS)
    set(command_prefix "python")
  endif()

  add_custom_command(
    OUTPUT "${destination}"
    COMMAND ${command_prefix} "${CMAKE_SOURCE_DIR}/tools/cmake/downloader.py" "${base_url}/${file_name}" "${destination}" "${hash}" > /dev/null
    COMMENT "Downloading: ${url}"
    VERBATIM
  )

  add_custom_target("${identifier}_downloader" DEPENDS "${destination}")
  set(downloadRemoteFile_destination "${destination}" PARENT_SCOPE)
endfunction()

# Generates a target named identifier_extractor that will extract the remote package
function(extractLocalArchive identifier anchor_file tarball_path working_directory)
  if(IS_ABSOLUTE "${anchor_file}")
    set(absolute_anchor_path "${anchor_file}")
  else()
    set(absolute_anchor_path "${CMAKE_CURRENT_BINARY_DIR}/${anchor_file}")
  endif()

  if("${tarball_path}" MATCHES ".tar.gz")
    set(external_tool "${CMAKE_COMMAND}")
    set(external_tool_parameters "-E" "tar" "xzf")

  elseif("${tarball_path}" MATCHES ".whl")
    set(external_tool "${CMAKE_COMMAND}")
    set(external_tool_parameters "-E" "tar" "x")
  endif()

  if(${ARGC} GREATER 4)
    foreach(additional_anchor ${ARGN})
      if(IS_ABSOLUTE "${additional_anchor}")
        list(APPEND additional_anchor_file_paths "${additional_anchor}")
      else()
        list(APPEND additional_anchor_file_paths "${CMAKE_CURRENT_BINARY_DIR}/${additional_anchor}")
      endif()
    endforeach()
  endif()

  add_custom_command(
    OUTPUT "${absolute_anchor_path}" ${additional_anchor_file_paths}
    COMMAND "${external_tool}" ${external_tool_parameters} "${tarball_path}" > /dev/null 2>&1
    DEPENDS "${identifier}_downloader"
    WORKING_DIRECTORY "${working_directory}"
    COMMENT "Extracting archive: ${tarball_path}"
    VERBATIM
  )

  add_custom_target("${identifier}_extractor" DEPENDS "${absolute_anchor_path}" ${additional_anchor_file_paths})
endfunction()

# Generates a empty imported or interface library named thirdparty_name that will depends on the targets
# that will download and extract the remote tarball
function(importThirdPartyBinaryLibrary name version hash library_type anchor_file_name)
  if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_name "macos")
  else()
    message(SEND_ERROR "Unrecognized system")
    return()
  endif()

  set(base_url "${THIRD_PARTY_REPOSITORY_URL}/third-party/pre-built/${platform_name}-x86_64")
  set(file_name "${name}-${version}.tar.gz")
  set(identifier "thirdparty_${name}")
  downloadRemoteFile("${identifier}" "${base_url}" "${file_name}" "${hash}")

  set(relative_anchor_path "${name}/${version}/${anchor_file_name}")

  if(${ARGC} GREATER 5)
    foreach(additional_anchor ${ARGN})
      list(APPEND additional_anchor_rel_paths "${name}/${version}/${additional_anchor}")
    endforeach()
  endif()

  extractLocalArchive("${identifier}" "${relative_anchor_path}" "${downloadRemoteFile_destination}" "${CMAKE_CURRENT_BINARY_DIR}" ${additional_anchor_rel_paths})

  if("${library_type}" STREQUAL "imported")
    add_library("${identifier}" STATIC IMPORTED GLOBAL)
  elseif("${library_type}" STREQUAL "interface")
    add_library("${identifier}" INTERFACE)
  else()
    message(SEND_ERROR "Invalid library type specified")
    return()
  endif()

  add_dependencies("${identifier}" "${identifier}_extractor")
  set(base_folder "${CMAKE_CURRENT_BINARY_DIR}/${name}/${version}")

  execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${base_folder}/include")
  set_target_properties("${identifier}" PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${base_folder}/include"
  )

  set(importThirdPartyBinaryLibrary_baseFolderPath "${base_folder}" PARENT_SCOPE)
endfunction()

# Generates an interface library named thirdparty_name that automatically includes the specified
# include folder. This library will depend on the downloader and extractor targets
function(importThirdPartySourceLibrary name version hash anchor_file include_folder)
  set(base_url "${THIRD_PARTY_REPOSITORY_URL}/third-party/source")
  set(file_name "${name}-${version}.tar.gz")
  set(identifier "thirdparty_${name}")
  downloadRemoteFile("${identifier}" "${base_url}" "${file_name}" "${hash}")
  extractLocalArchive("${identifier}" "${anchor_file}" "${downloadRemoteFile_destination}" "${CMAKE_CURRENT_BINARY_DIR}")

  add_library("${identifier}" INTERFACE)
  add_dependencies("${identifier}" "${identifier}_extractor")

  set(base_folder "${CMAKE_CURRENT_BINARY_DIR}")
  execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${base_folder}/${include_folder}")
  target_include_directories("${identifier}" INTERFACE "${base_folder}/${include_folder}")
endfunction()

# Initializes the PYTHONPATH folder in the binary directory, used to run the codegen scripts
function(initializePythonPathFolder)  
  add_custom_command(
    OUTPUT "${PYTHON_PATH}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${PYTHON_PATH}"
    COMMENT "Initializing custom PYTHONPATH: ${PYTHON_PATH}"
  )

  add_custom_target(thirdparty_pythonpath DEPENDS "${PYTHON_PATH}")
endfunction()

# Imports a remote Python module inside the PYTHONPATH folder (previously initialized
# with the initializePythonPathFolder() function). The target will be named thirdparty_identifier
function(importRemotePythonModule identifier base_url file_name hash)
  set(target_name "thirdparty_pythonmodule_${identifier}")
  downloadRemoteFile("${target_name}" "${base_url}" "${file_name}" "${hash}")

  extractLocalArchive("${target_name}" "${PYTHON_PATH}/${identifier}" "${downloadRemoteFile_destination}" "${PYTHON_PATH}")
  add_dependencies("${target_name}_extractor" thirdparty_pythonpath)

  add_library("${target_name}" INTERFACE)
  add_dependencies("${target_name}" "${target_name}_extractor")
endfunction()

# Make sure that globals.cmake and options.cmake have been included
if("${PYTHON_PATH}" STREQUAL "")
  message(FATAL_ERROR "The PYTHON_PATH variable was not found. Has globals.cmake been included?")
endif()

if("${THIRD_PARTY_REPOSITORY_URL}" STREQUAL "")
  message(FATAL_ERROR "The THIRD_PARTY_REPOSITORY_URL variable was not found. Has options.cmake been included?")
endif()

osqueryThirdpartyMain()
