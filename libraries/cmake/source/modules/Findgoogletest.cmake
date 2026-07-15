# FreeBSD: use system googletest from devel/googletest
# osquery uses gtest_prod.h macros (FRIEND_TEST) even with tests disabled,
# so we need an INTERFACE include-only target.
if(NOT TARGET thirdparty_googletest)
  add_library(thirdparty_googletest INTERFACE)
  target_include_directories(thirdparty_googletest SYSTEM INTERFACE
    /usr/local/include
  )
endif()

# Also provide the _headers alias that some sources reference.
if(NOT TARGET thirdparty_googletest_headers)
  add_library(thirdparty_googletest_headers INTERFACE)
  target_include_directories(thirdparty_googletest_headers SYSTEM INTERFACE
    /usr/local/include
  )
endif()

# Provide empty stubs for gtest/gmock targets in case anything references them
# (tests are disabled, but the CMake graph may still reference these names).
foreach(_t gtest gmock gtest_main gmock_main)
  if(NOT TARGET ${_t})
    add_library(${_t} INTERFACE)
    target_include_directories(${_t} SYSTEM INTERFACE /usr/local/include)
  endif()
endforeach()
