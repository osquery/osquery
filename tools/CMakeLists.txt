# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(toolsMain)
  add_subdirectory("codegen")
  if(BUILD_TESTING)
    add_subdirectory("tests")
  endif()
endfunction()

toolsMain()
