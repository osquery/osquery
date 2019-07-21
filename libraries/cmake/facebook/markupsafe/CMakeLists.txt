# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(markupsafeMain)
  set(name "markupsafe")
  set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/linux-x86_64")
  set(file_name "MarkupSafe-1.1.0-cp37-cp37m-manylinux1_x86_64.whl")

  if(DEFINED PLATFORM_LINUX)
    # Original SHA1 was 17ad72c7ce71a33144455048af1a5a3538ca1750
    set(hash "d9ac82be533394d341b41d78aca7ed0e0f4ba5a2231602e2f05aa87f25c51672")
  elseif(DEFINED PLATFORM_MACOS)
    # Original SHA1 was eb3e78cf203e2cd0eaa406ccf157cb613f9f28d8
    set(hash "1f19ef5d3908110e1e891deefb5586aae1b49a7440db952454b4e281b41620cd")
    set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/macos-x86_64")
    set(file_name "MarkupSafe-1.1.0-cp37-cp37m-macosx_10_6_intel.whl")
  elseif(DEFINED PLATFORM_WINDOWS)
    # Original SHA1 was 0bbf7dc728394c47e375cb62e6690ab8cc5fa396
    set(hash "52b07fbc32032c21ad4ab060fec137b76eb804c4b9a1c7c7dc562549306afad2")
    set(base_url "https://s3.amazonaws.com/osquery-packages/third-party/pre-built/windows-x86_64")
    set(file_name "MarkupSafe-1.1.0-cp36-cp36m-win_amd64.whl")
  elseif(DEFINED PLATFORM_FREEBSD)
    # Original SHA1 was 925a0b34f901f99aeadd4d91a1dd676b3eed494f
    set(hash "aa")
  else()
    return()
  endif()

  importRemotePythonModule("${name}" "${base_url}" "${file_name}" "${hash}")
endfunction()

markupsafeMain()
