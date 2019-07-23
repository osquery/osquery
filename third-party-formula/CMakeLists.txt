# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

include(ExternalProject)

function(osqueryThirdpartyMain)
  initializePythonPathFolder()
  osqueryThirdpartyBuildMain()

  # Python modules
  add_subdirectory("jinja2")
  add_subdirectory("markupsafe")

  # Placeholder or build-from-source
  add_subdirectory("glibc")
  add_subdirectory("sqlite")
  add_subdirectory("googletest")

  # Ordered recursive dependencies
  add_subdirectory("zlib")
  add_subdirectory("bzip2")
  add_subdirectory("libxml2")
  add_subdirectory("lzma")
  add_subdirectory("openssl")
  add_subdirectory("gflags")
  add_subdirectory("glog")
  add_subdirectory("boost")
  add_subdirectory("libgpg-error")
  add_subdirectory("libgcrypt")
  add_subdirectory("ncurses")
  add_subdirectory("util-linux")
  add_subdirectory("popt")
  add_subdirectory("rapidjson")
  add_subdirectory("augeas")
  add_subdirectory("aws-sdk-cpp")
  add_subdirectory("berkeley-db")
  add_subdirectory("libarchive")
  add_subdirectory("libaudit")
  add_subdirectory("libdevmapper")
  add_subdirectory("libcryptsetup")
  add_subdirectory("libelfin")
  add_subdirectory("libiptables")
  add_subdirectory("libmagic")
  add_subdirectory("librpm")
  add_subdirectory("libudev")
  add_subdirectory("linenoise-ng")
  add_subdirectory("lldpd")
  add_subdirectory("libdpkg")
  add_subdirectory("librdkafka")
  add_subdirectory("rocksdb")
  add_subdirectory("sleuthkit")
  add_subdirectory("smartmontools")
  add_subdirectory("ssdeep-cpp")
  add_subdirectory("thrift")
  add_subdirectory("yara")
  add_subdirectory("zstd")
endfunction()

function(osqueryThirdpartyBuildMain)
  # For our custom ExternalProject wrapper we define argument groups.
  add_custom_target(thirdparty_prebuilt)
endfunction()

function(definePrebuiltProject name)
  set(identifier "thirdparty_build_${name}")
  if("${CMAKE_GENERATOR}" STREQUAL "Ninja")
    # Ninja build will error with "$(MAKE)" output
    return()
  endif()

  # Create a target to hold the arguments from the function call.
  set(props "${identifier}_props")
  add_custom_target(${props})
  _ep_parse_arguments(definePrebuiltProject ${props} _CEP_ "${ARGN}")

  # Access arguments as propertoes.
  get_property(depends_list TARGET ${props} PROPERTY _CEP_DEPENDS)
  foreach(depends ${depends_list})
    list(APPEND depends_targets "thirdparty_build_${depends}")
  endforeach()

  get_property(url TARGET ${props} PROPERTY _CEP_URL)
  get_property(hash TARGET ${props} PROPERTY _CEP_SHA256)
  get_property(patches TARGET ${props} PROPERTY _CEP_PATCHES)
  get_property(configure_command TARGET ${props} PROPERTY _CEP_CONFIGURE)
  get_property(build_command TARGET ${props} PROPERTY _CEP_BUILD)
  get_property(install_command TARGET ${props} PROPERTY _CEP_INSTALL)
  get_property(build_in_source TARGET ${props} PROPERTY _CEP_BUILD_IN_SOURCE)

  set(patch_glue)
  foreach(patch ${patches})
    list(APPEND patch_command ${patch_glue}
      patch -p1 < ${CMAKE_CURRENT_SOURCE_DIR}/${patch})
    set(patch_glue &&)
  endforeach()

  if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_name "macos")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_name "windows")
  else()
    message(FATAL_ERROR "Unrecognized system")
    return()
  endif()

  set(install_prefix "${THIRD_PARTY_PREBUILT_PATH}/${platform_name}-x86_64")

  # 'Forward' them to ExternalProject
  ExternalProject_Add(${identifier}
    URL ${url}
    URL_HASH SHA256=${hash}
    INSTALL_DIR "${install_prefix}"
    DEPENDS ${depends_targets}
    PATCH_COMMAND ${patch_command}
    CONFIGURE_COMMAND ${configure_command}
    BUILD_COMMAND ${build_command}
    INSTALL_COMMAND ${install_command}
    EXCLUDE_FROM_ALL ON
    BUILD_IN_SOURCE ${build_in_source}
  )
  add_dependencies(thirdparty_prebuilt "${identifier}")
endfunction()

# Generates a target named identifier_downloader that will acquire the remote file while also verifying
# its hash
function(downloadRemoteFile identifier base_url file_name hash)
  set(destination "${CMAKE_CURRENT_BINARY_DIR}/${file_name}")
  set(url "${base_url}/${file_name}")

  set(command_prefix "${EX_TOOL_PYTHON2_EXECUTABLE_PATH}")

  add_custom_command(
    OUTPUT "${destination}"
    COMMAND ${command_prefix} "${CMAKE_SOURCE_DIR}/tools/cmake/downloader.py" "${base_url}/${file_name}" "${destination}" "${hash}"
    COMMENT "Downloading: ${url}"
    VERBATIM
  )

  add_custom_target("${identifier}_downloader" DEPENDS "${destination}")
  set(downloadRemoteFile_destination "${destination}" PARENT_SCOPE)
endfunction()

# Generates a target named identifier_extractor that will extract the remote package
function(extractLocalArchive identifier anchor_file archive_path working_directory)
  if(IS_ABSOLUTE "${anchor_file}")
    set(absolute_anchor_path "${anchor_file}")
  else()
    set(absolute_anchor_path "${working_directory}/${anchor_file}")
  endif()

  if("${archive_path}" MATCHES ".tar.gz" OR "${archive_path}" MATCHES ".zip")
    set(external_tool "${CMAKE_COMMAND}")
    set(external_tool_parameters "-E" "tar" "xzf")

  elseif("${archive_path}" MATCHES ".whl")
    set(external_tool "${CMAKE_COMMAND}")
    set(external_tool_parameters "-E" "tar" "x")
  endif()

  if(${ARGC} GREATER 4)
    foreach(additional_anchor ${ARGN})
      if(IS_ABSOLUTE "${additional_anchor}")
        list(APPEND additional_anchor_file_paths "${additional_anchor}")
      else()
        list(APPEND additional_anchor_file_paths "${working_directory}/${additional_anchor}")
      endif()
    endforeach()
  endif()

  add_custom_command(
    OUTPUT "${absolute_anchor_path}" ${additional_anchor_file_paths}
    COMMAND "${external_tool}" ${external_tool_parameters} "${archive_path}"
    DEPENDS "${identifier}_downloader"
    WORKING_DIRECTORY "${working_directory}"
    COMMENT "Extracting archive: ${archive_path}"
    VERBATIM
  )

  add_custom_target("${identifier}_extractor" DEPENDS "${absolute_anchor_path}" ${additional_anchor_file_paths})
endfunction()

function(importThirdPartyBinaryLibrary name anchor_file_name)
  if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_name "macos")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_name "windows")
  else()
    message(FATAL_ERROR "Unrecognized system")
    return()
  endif()

  set(identifier "thirdparty_${name}")
  set(base_path "${THIRD_PARTY_PREBUILT_PATH}/${platform_name}-x86_64")

  # Just the name of the file
  set(relative_anchor_path "${anchor_file_name}")

  if(${ARGC} GREATER 2)
    foreach(additional_anchor ${ARGN})
      list(APPEND additional_anchor_rel_paths "${additional_anchor}")
    endforeach()
  endif()

  if(additional_anchor_rel_paths)
    add_osquery_library("${identifier}" INTERFACE IMPORTED GLOBAL)
    set_target_properties("${identifier}" PROPERTIES INTERFACE_BINARY_DIR "${base_path}")

    list(APPEND libraries "${relative_anchor_path}")
    list(APPEND libraries "${additional_anchor_rel_paths}")

    foreach(library ${libraries})
      get_filename_component(library_name "${library}" NAME_WE)
      add_osquery_library("${identifier}_${library_name}" STATIC IMPORTED GLOBAL)
      set_target_properties("${identifier}_${library_name}" PROPERTIES IMPORTED_LOCATION "${base_path}/${library}")
      target_link_libraries("${identifier}" INTERFACE "${identifier}_${library_name}")
    endforeach()
  else()
    add_osquery_library("${identifier}" STATIC IMPORTED GLOBAL)
    set_target_properties("${identifier}" PROPERTIES IMPORTED_LOCATION "${base_path}/${relative_anchor_path}")
  endif()

  execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${base_path}/include")
  target_include_directories("${identifier}" INTERFACE "${base_path}/include")

  set(importThirdPartyBinaryLibrary_baseFolderPath "${base_path}" PARENT_SCOPE)
endfunction()

function(importThirdPartyHeaderOnlyLibrary library_type name anchor_file include_folder)
  if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_name "macos")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_name "windows")
  else()
    message(FATAL_ERROR "Unrecognized system")
    return()
  endif()

  set(identifier "thirdparty_${name}")
  set(base_path "${THIRD_PARTY_PREBUILT_PATH}/${platform_name}-x86_64")

  add_osquery_library("${identifier}" INTERFACE)
  target_include_directories("${identifier}" INTERFACE "${base_path}/${include_folder}")
endfunction()

# Generates a empty imported or interface library named thirdparty_name that will depends on the targets
# that will download and extract the remote tarball
function(importThirdPartyBinaryLibrary_DEPRECATED name version hash anchor_file_name)
  if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
  elseif(DEFINED PLATFORM_MACOS)
    set(platform_name "macos")
  elseif(DEFINED PLATFORM_WINDOWS)
    set(platform_name "windows")
  else()
    message(FATAL_ERROR "Unrecognized system")
    return()
  endif()

  set(base_url "${THIRD_PARTY_REPOSITORY_URL}/third-party/pre-built/${platform_name}-x86_64")
  set(file_name "${name}-${version}.tar.gz")
  set(identifier "thirdparty_${name}")
  downloadRemoteFile("${identifier}" "${base_url}" "${file_name}" "${hash}")

  set(relative_anchor_path "${name}/${version}/${anchor_file_name}")

  if(${ARGC} GREATER 4)
    foreach(additional_anchor ${ARGN})
      list(APPEND additional_anchor_rel_paths "${name}/${version}/${additional_anchor}")
    endforeach()
  endif()

  extractLocalArchive("${identifier}" "${relative_anchor_path}" "${downloadRemoteFile_destination}" "${CMAKE_CURRENT_BINARY_DIR}" ${additional_anchor_rel_paths})

  set(base_folder "${CMAKE_CURRENT_BINARY_DIR}/${name}/${version}")

  if(additional_anchor_rel_paths)
    add_osquery_library("${identifier}" INTERFACE IMPORTED GLOBAL)
    set_target_properties("${identifier}" PROPERTIES INTERFACE_BINARY_DIR "${base_folder}")

    list(APPEND libraries "${relative_anchor_path}")
    list(APPEND libraries "${additional_anchor_rel_paths}")

    foreach(library ${libraries})
      get_filename_component(library_name "${library}" NAME_WE)
      add_osquery_library("${identifier}_${library_name}" STATIC IMPORTED GLOBAL)
      set_target_properties("${identifier}_${library_name}" PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/${library}")
      target_link_libraries("${identifier}" INTERFACE "${identifier}_${library_name}")
    endforeach()
  else()
    add_osquery_library("${identifier}" STATIC IMPORTED GLOBAL)
    set_target_properties("${identifier}" PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/${relative_anchor_path}")
  endif()

  add_dependencies("${identifier}" "${identifier}_extractor")

  # So that's possible to download and extract dependencies before building, to have the IDE working correctly
  add_dependencies("prepare_for_ide" "${identifier}_extractor")

  execute_process(COMMAND "${CMAKE_COMMAND}" -E make_directory "${base_folder}/include")
  target_include_directories("${identifier}" INTERFACE "${base_folder}/include")

  set(importThirdPartyBinaryLibrary_baseFolderPath "${base_folder}" PARENT_SCOPE)
endfunction()

# Generates an interface library named thirdparty_name that automatically includes the specified
# include folder. This library will depend on the downloader and extractor targets
function(importThirdPartyHeaderOnlyLibrary_DEPRECATED library_type name version hash anchor_file include_folder)

  if("${library_type}" STREQUAL "SOURCE")
    set(base_url "${THIRD_PARTY_REPOSITORY_URL}/third-party/src")
  elseif("${library_type}" STREQUAL "PREBUILT")
    if(DEFINED PLATFORM_LINUX)
    set(platform_name "linux")
    elseif(DEFINED PLATFORM_MACOS)
      set(platform_name "macos")
    elseif(DEFINED PLATFORM_WINDOWS)
      set(platform_name "windows")
    else()
      message(FATAL_ERROR "Unrecognized system")
      return()
    endif()

    set(base_url "${THIRD_PARTY_REPOSITORY_URL}/third-party/pre-built/${platform_name}-x86_64")
    set(base_folder "${CMAKE_CURRENT_BINARY_DIR}/${name}/${version}")
  else()
    set(base_folder "${CMAKE_CURRENT_BINARY_DIR}")
    message(FATAL_ERROR "Unknown header only library type ${library_type}")
  endif()

  set(file_name "${name}-${version}.tar.gz")
  set(identifier "thirdparty_${name}")
  downloadRemoteFile("${identifier}" "${base_url}" "${file_name}" "${hash}")
  extractLocalArchive("${identifier}" "${base_folder}/${anchor_file}" "${downloadRemoteFile_destination}" "${CMAKE_CURRENT_BINARY_DIR}")

  add_osquery_library("${identifier}" INTERFACE)
  add_dependencies("${identifier}" "${identifier}_extractor")

  # So that's possible to download and extract dependencies before building, to have the IDE working correctly
  add_dependencies("prepare_for_ide" "${identifier}_extractor")

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
  add_custom_target(thirdparty_python_modules)
endfunction()

# Imports a remote Python module inside the PYTHONPATH folder (previously initialized
# with the initializePythonPathFolder() function). The target will be named thirdparty_identifier
function(importRemotePythonModule identifier base_url file_name hash)
  set(target_name "thirdparty_pythonmodule_${identifier}")
  downloadRemoteFile("${target_name}" "${base_url}" "${file_name}" "${hash}")

  extractLocalArchive("${target_name}" "${PYTHON_PATH}/${identifier}" "${downloadRemoteFile_destination}" "${PYTHON_PATH}")
  add_dependencies("${target_name}_extractor" thirdparty_pythonpath)

  add_osquery_library("${target_name}" INTERFACE)
  add_dependencies("${target_name}" "${target_name}_extractor")
  add_dependencies("thirdparty_python_modules" "${target_name}")
endfunction()

# Make sure that globals.cmake and options.cmake have been included
if("${PYTHON_PATH}" STREQUAL "")
  message(FATAL_ERROR "The PYTHON_PATH variable was not found. Has globals.cmake been included?")
endif()

if("${THIRD_PARTY_REPOSITORY_URL}" STREQUAL "")
  message(FATAL_ERROR "The THIRD_PARTY_REPOSITORY_URL variable was not found. Has options.cmake been included?")
endif()

osqueryThirdpartyMain()
