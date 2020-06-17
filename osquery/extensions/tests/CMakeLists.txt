# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(osqueryExtensionsTestsMain)
  generateOsqueryExtensionsTestsTest()
endfunction()

function(generateOsqueryExtensionsTestsTest)
  add_osquery_executable(osquery_extensions_extensiontests-test extensions.cpp)

  target_link_libraries(osquery_extensions_extensiontests-test PRIVATE
    osquery_cxx_settings
    osquery_sdk_pluginsdk
    osquery_extensions_implthrift
    thirdparty_googletest
  )
endfunction()

osqueryExtensionsTestsMain()
