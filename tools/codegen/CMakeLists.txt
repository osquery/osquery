# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(toolsCodegenMain)
  # Prepare the gentable.py script
  generateGentable()
endfunction()

# Generates a runnable gentable.py script; unfortunately, upstream has scattered
# the required files around, so we need to piece them together
function(generateGentable)
  set(gentable_working_directory "${CMAKE_CURRENT_BINARY_DIR}/gentable")

  set(module_path "osquery/tools/tests")
  generatePythonModulePath("${gentable_working_directory}" "${module_path}" "gentable_dependency_")

  set(utils_file_path "${gentable_working_directory}/${module_path}/utils.py")
  add_custom_command(
    OUTPUT "${utils_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${CMAKE_SOURCE_DIR}/tools/tests/utils.py" "${utils_file_path}"
    DEPENDS "${generatePythonModulePath_rootTarget}"
  )

  add_custom_target("codegen_gentable_utils_dependency" DEPENDS "${utils_file_path}")

  set(gentable_file_path "${gentable_working_directory}/gentable.py")
  set(source_base_path "${CMAKE_CURRENT_SOURCE_DIR}")
  add_custom_command(
    OUTPUT "${gentable_file_path}"
    COMMAND "${CMAKE_COMMAND}" -E create_symlink "${source_base_path}/gentable.py" "${gentable_file_path}"
    DEPENDS "codegen_gentable_utils_dependency" "thirdparty_python_modules"
  )

  add_custom_target("codegen_gentable" DEPENDS "${gentable_file_path}")

  # Save the path in a property, so that we can reference it in the generateTables() function
  # when it is called from another scope
  set_property(GLOBAL PROPERTY CODEGEN_GENTABLE_PATH "${gentable_file_path}")
  set_property(GLOBAL PROPERTY CODEGEN_GENTABLE_WORKINGDIRECTORY "${gentable_working_directory}")
endfunction()

# This function generates a path in a similar way to `mkdir -p` while also creating
# a `__init__.py` file in each folder
function(generatePythonModulePath base_path path identifier)
  string(REPLACE "/" ";" path_components "${path}")

  set(current_base_path "${base_path}")
  set(index 1)

  foreach(component ${path_components})
    set(current_path "${current_base_path}/${component}")
    set(init_file_path "${current_path}/__init__.py")

    add_custom_command(
      OUTPUT "${init_file_path}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${current_path}"
      COMMAND "${CMAKE_COMMAND}" -E touch "${init_file_path}"
    )

    set(target_name "${identifier}_generator_${index}")
    add_custom_target("${target_name}" DEPENDS "${init_file_path}")
    list(APPEND target_list "${target_name}")

    set(current_base_path "${current_path}")
    math(EXPR index "${index}+1")
  endforeach()

  set(root_target "${identifier}_generator")
  add_custom_target("${root_target}")
  
  set(previous_target "${root_target}")
  list(REVERSE target_list)

  foreach(target ${target_list})
    add_dependencies("${previous_target}" "${target}")
    set(previous_target "${target}")
  endforeach()

  set(generatePythonModulePath_rootTarget "${root_target}" PARENT_SCOPE)
endfunction()

# Generates the table code from a list of table spec files
function(generateTables category)
  # Acquire the gentable path and working directory from the global properties (set from
  # generateGentable())
  get_property(gentable_file_path GLOBAL PROPERTY CODEGEN_GENTABLE_PATH)
  get_property(gentable_working_directory GLOBAL PROPERTY CODEGEN_GENTABLE_WORKINGDIRECTORY)

  if("${gentable_file_path}" STREQUAL "")
    message(SEND_ERROR "The gentable.py tool was not found!")
    return()
  endif()

  if("${gentable_working_directory}" STREQUAL "")
    message(SEND_ERROR "The gentable.py working directory was not found!")
    return()
  endif()

  # Make sure we actually have parameters
  if(${ARGC} EQUAL 1)
    message(SEND_ERROR "No spec file specified")
    return()
  endif()

  # Convert all relative paths to absolute paths
  foreach(relative_table_spec ${ARGN})
    list(APPEND table_spec_list "${CMAKE_SOURCE_DIR}/specs/${relative_table_spec}")
  endforeach()

  # Iterate through each table spec file
  set(output_folder "${CMAKE_CURRENT_BINARY_DIR}/${category}")

  foreach(table_spec ${table_spec_list})
    # Use the file name as table name
    get_filename_component(table_name "${table_spec}" NAME_WE)
    set(generated_source_code "${output_folder}/${table_name}.cpp")
    
    set(generated_headers_folder "${output_folder}/osquery/rows")
    set(generated_header_code "${generated_headers_folder}/${table_name}.h")

    # Set up the generator
    get_filename_component(source_code_intermediate_directories "${generated_source_code}" DIRECTORY)

    if("${category}" STREQUAL "foreign")
      set(optional_foreign_parameter "--foreign")
    endif()

    set(env_path_separator ":")
    if(DEFINED PLATFORM_WINDOWS)
      set(env_path_separator ";")
    endif()

    add_custom_command(
      OUTPUT "${generated_source_code}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${source_code_intermediate_directories}"
      COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${gentable_working_directory}${env_path_separator}${PYTHON_PATH}" "${EX_TOOL_PYTHON3_EXECUTABLE_PATH}" "${gentable_file_path}" --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${optional_foreign_parameter} "${table_spec}" "${generated_source_code}"
      WORKING_DIRECTORY "${gentable_working_directory}"
      DEPENDS codegen_gentable "${table_spec}"
      COMMENT "Generating code for table ${category}/${table_name}..."
      VERBATIM
    )

    add_custom_command(
      OUTPUT "${generated_header_code}"
      COMMAND "${CMAKE_COMMAND}" -E make_directory "${generated_headers_folder}"
      COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${gentable_working_directory}${env_path_separator}${PYTHON_PATH}" "${EX_TOOL_PYTHON3_EXECUTABLE_PATH}" "${gentable_file_path}" --header --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${optional_foreign_parameter} "${table_spec}" "${generated_header_code}"
      WORKING_DIRECTORY "${gentable_working_directory}"
      DEPENDS codegen_gentable "${table_spec}"
      COMMENT "Generating header for table ${category}/${table_name}..."
      VERBATIM
    )

    set(table_target_name "codegen_gentable_${category}_${table_name}")
    add_custom_target("${table_target_name}" DEPENDS "${generated_source_code}")

    set(header_generator_target_name "codegen_gentable_${category}_${table_name}_header")
    add_custom_target("${header_generator_target_name}" DEPENDS "${generated_header_code}")

    set(header_library_name "osquery_rows_${table_name}_header")
    add_osquery_library("${header_library_name}" INTERFACE)
    add_dependencies("${header_library_name}" "${header_generator_target_name}")
    target_include_directories("${header_library_name}" INTERFACE "${output_folder}")

    list(APPEND generated_target_list "${table_target_name}")
  endforeach()

  # Return the base folder
  set(generateTables_output ${output_folder} PARENT_SCOPE)
  set(generateTables_targetList ${generated_target_list} PARENT_SCOPE)
endfunction()

function(generateTableCategoryAmalgamation category_name)
  # Make sure we actually have parameters
  if(${ARGC} EQUAL 1)
    message(SEND_ERROR "No spec file specified")
    return()
  endif()

  set(category_spec_files ${ARGN})

  # Generate the source files
  generateTables("${category_name}" ${category_spec_files})

  list(TRANSFORM category_spec_files PREPEND "${CMAKE_SOURCE_DIR}/specs/")

  # Amalgamate all the source files into a single one
  set(amalgamation_file "${CMAKE_CURRENT_BINARY_DIR}/amalgamated_${category_name}_tables.cpp")

  if("${category_name}" STREQUAL "foreign")
    set(amalgamation_type "--foreign")
  else()
    set(amalgamation_type --category "${category_name}")
  endif()

  add_custom_command(
    OUTPUT "${amalgamation_file}"
    COMMAND "${CMAKE_COMMAND}" -E env "PYTHONPATH=${PYTHON_PATH}" "${EX_TOOL_PYTHON3_EXECUTABLE_PATH}" "${CMAKE_SOURCE_DIR}/tools/codegen/amalgamate.py" --templates "${CMAKE_SOURCE_DIR}/tools/codegen/templates" ${amalgamation_type} --sources "${generateTables_output}" --output "${amalgamation_file}"
    COMMENT "Generating amalgamation file for the ${category_name} tables..."
    DEPENDS "${category_spec_files}" ${generateTables_targetList} "thirdparty_python_modules"
  )

  # Build the library
  set(target_name "codegen_${category_name}_tables")

  add_osquery_library("${target_name}" EXCLUDE_FROM_ALL "${amalgamation_file}")
  target_link_libraries("${target_name}" PUBLIC osquery_events)

  # Return the target name to the caller
  set(generateTableCategoryAmalgamation_output "${target_name}" PARENT_SCOPE)
endfunction()

toolsCodegenMain()
