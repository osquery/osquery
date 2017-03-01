# -*- mode: cmake; -*-
# - osquery external project builds
#
# Symlink directories for extensions or modules here.
# If a directory includes: "extension_NAME" it is built as an extension.
# If a directory includes: "module_NAME" it is built as a module.

add_custom_target(externals)
add_definitions(-DOSQUERY_EXTERNAL)

macro(SUBDIRLIST OUTPUT PWD)
  file(GLOB children RELATIVE ${PWD} "${PWD}/*")
  set(DIRS "")
  foreach(child ${children})
    get_filename_component(full_child "${PWD}/${child}" REALPATH)
    if(IS_DIRECTORY "${full_child}")
      list(APPEND DIRS "${PWD}/${child}")
    elseif(NOT "${child}" STREQUAL "CMakeLists.txt")
      WARNING_LOG("External project: ${full_child} must be a directory")
    endif()
  endforeach()
  set(${OUTPUT} ${DIRS})
endmacro()

# Discover each directory, which contains the implementation for an extension
# or module, usually symlinked.
SUBDIRLIST(EXTERNAL_PROJECTS "${CMAKE_SOURCE_DIR}/external")

# Each project may:
#   1. Be named "external_PROJECT_NAME", all .cpp, .c, .mm files will be compiled.
#   2. Be named "module_PROJECT_NAME", the same applies.
#   3. Contain a "CMakeLists.txt", the project will be added to CMake's evaluation.
foreach(external_project ${EXTERNAL_PROJECTS})
  if(EXISTS "${external_project}/CMakeLists.txt")
    add_subdirectory("${external_project}")
  else()
    file(GLOB_RECURSE PROJECT_FILES "${external_project}/*")
    set(PROJECT_SOURCES "")
    foreach(source ${PROJECT_FILES})
      if(${source} MATCHES "^.*(cpp|c|mm)$")
        list(APPEND PROJECT_SOURCES ${source})
      endif()
    endforeach()
    get_filename_component(PROJECT_NAME "${external_project}" NAME)
    if("${PROJECT_NAME}" MATCHES "(^extension_.*)")
      ADD_OSQUERY_EXTENSION(external_${PROJECT_NAME} ${PROJECT_SOURCES})
      add_dependencies(externals external_${PROJECT_NAME})
    elseif("${PROJECT_NAME}" MATCHES "(^module_.*)")
      ADD_OSQUERY_MODULE(external_${PROJECT_NAME} ${PROJECT_SOURCES})
      add_dependencies(externals external_${PROJECT_NAME})
    else()
      WARNING_LOG("External project: ${external_project} is incorrectly named")
    endif()
  endif()
endforeach()
