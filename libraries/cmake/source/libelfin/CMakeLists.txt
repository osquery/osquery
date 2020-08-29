# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libelfinMain)
  libelfinElf()
  libelfinDwarf()

  add_library(thirdparty_libelfin INTERFACE)
  target_link_libraries(thirdparty_libelfin INTERFACE
    thirdparty_libelfin_elf
    thirdparty_libelfin_dwarf
  )
endfunction()

function(libelfinElf)
  set(library_root "${OSQUERY_libelfin_ROOT_DIR}/elf")

  add_library(thirdparty_libelfin_elf
    "${library_root}/mmap_loader.cc"
    "${library_root}/elf.cc"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/elf/to_string.cc"
  )

  target_link_libraries(thirdparty_libelfin_elf PRIVATE
    thirdparty_cxx_settings
  )

  # The original package built for Buck was built installing
  # the library inside the wrong prefix; let's try to keep this
  # working without changing the source code!
  set(public_header_list
    elf++.hh
    data.hh
    to_hex.hh
    common.hh
  )

  foreach(public_header ${public_header_list})
    configure_file(
      "${library_root}/${public_header}"
      "${OSQUERY_libelfin_ROOT_DIR}/libelfin/elf/${public_header}"
      COPYONLY
    )
  endforeach()

  target_include_directories(thirdparty_libelfin_elf PRIVATE
    "${OSQUERY_libelfin_ROOT_DIR}"
    "${library_root}"
  )

  target_include_directories(thirdparty_libelfin_elf SYSTEM INTERFACE
    "${OSQUERY_libelfin_ROOT_DIR}"
  )
endfunction()

function(libelfinDwarf)
  set(library_root "${OSQUERY_libelfin_ROOT_DIR}/dwarf")

  add_library(thirdparty_libelfin_dwarf
    "${library_root}/cursor.cc"
    "${library_root}/die_str_map.cc"
    "${library_root}/attrs.cc"
    "${library_root}/abbrev.cc"
    "${library_root}/rangelist.cc"
    "${library_root}/value.cc"
    "${library_root}/line.cc"
    "${library_root}/expr.cc"
    "${library_root}/die.cc"
    "${library_root}/elf.cc"
    "${library_root}/dwarf.cc"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/dwarf/to_string.cc"
  )

  target_link_libraries(thirdparty_libelfin_dwarf PRIVATE
    thirdparty_cxx_settings
  )

  # The original package built for Buck was built installing
  # the library inside the wrong prefix; let's try to keep this
  # working without changing the source code!
  set(public_header_list
    dwarf++.hh
    internal.hh
    data.hh
    small_vector.hh
  )

  foreach(public_header ${public_header_list})
    configure_file(
      "${library_root}/${public_header}"
      "${OSQUERY_libelfin_ROOT_DIR}/libelfin/dwarf/${public_header}"
      COPYONLY
    )
  endforeach()

  target_include_directories(thirdparty_libelfin_dwarf PRIVATE
    "${OSQUERY_libelfin_ROOT_DIR}"
    "${library_root}"
  )

  target_include_directories(thirdparty_libelfin_dwarf SYSTEM INTERFACE
    "${OSQUERY_libelfin_ROOT_DIR}"
  )
endfunction()

libelfinMain()
