# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(krabsetwLibraryMain) 
  if(NOT DEFINED PLATFORM_WINDOWS)
    message(FATAL_ERROR "krabsetw can only be imported when compiling for Windows")
  endif()

  if(NOT STREQUAL "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    message(FATAL_ERROR "MSVC is required when building krabsetw")
  endif()
  
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}")  
    
  add_library(thirdparty_krabsetw "${CMAKE_CURRENT_SOURCE_DIR}/config/krabs.cpp" )
  
  target_compile_options(thirdparty_krabsetw PRIVATE
    -DUNICODE
  )  
 
  target_include_directories(thirdparty_krabsetw PRIVATE  
	"${library_root}/src/krabs"
	"${library_root}/src/krabs/krabs"
	"${library_root}/src/krabs/krabs/filtering"
	"${library_root}/src/krabs/krabs/testing"
  )
  
  target_link_libraries(thirdparty_krabsetw PRIVATE thirdparty_cxx_settings)
  
  target_include_directories(thirdparty_krabsetw SYSTEM INTERFACE  
	"${library_root}/src/krabs"
	"${library_root}/src/krabs/krabs"
	"${library_root}/src/krabs/krabs/filtering"
	"${library_root}/src/krabs/krabs/testing"
  )
endfunction()

krabsetwLibraryMain()
