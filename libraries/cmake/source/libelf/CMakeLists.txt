# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(libelfMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  set(libeu_sources
    "${library_root}/lib/xasprintf.c"
    "${library_root}/lib/xstrdup.c"
    "${library_root}/lib/xstrndup.c"
    "${library_root}/lib/xmalloc.c"
    "${library_root}/lib/next_prime.c"
    "${library_root}/lib/crc32.c"
    "${library_root}/lib/crc32_file.c"
    "${library_root}/lib/eu-search.c"
    "${library_root}/lib/color.c"
    "${library_root}/lib/error.c"
    "${library_root}/lib/printversion.c"
  )

  set(libelf_sources
    "${library_root}/libelf/elf_version.c"
    "${library_root}/libelf/elf_hash.c"
    "${library_root}/libelf/elf_error.c"
    "${library_root}/libelf/elf_fill.c"
    "${library_root}/libelf/elf_begin.c"
    "${library_root}/libelf/elf_next.c"
    "${library_root}/libelf/elf_rand.c"
    "${library_root}/libelf/elf_end.c"
    "${library_root}/libelf/elf_kind.c"
    "${library_root}/libelf/gelf_getclass.c"
    "${library_root}/libelf/elf_getbase.c"
    "${library_root}/libelf/elf_getident.c"
    "${library_root}/libelf/elf32_fsize.c"
    "${library_root}/libelf/elf64_fsize.c"
    "${library_root}/libelf/gelf_fsize.c"
    "${library_root}/libelf/elf32_xlatetof.c"
    "${library_root}/libelf/elf32_xlatetom.c"
    "${library_root}/libelf/elf64_xlatetof.c"
    "${library_root}/libelf/elf64_xlatetom.c"
    "${library_root}/libelf/gelf_xlate.c"
    "${library_root}/libelf/elf32_getehdr.c"
    "${library_root}/libelf/elf64_getehdr.c"
    "${library_root}/libelf/gelf_getehdr.c"
    "${library_root}/libelf/elf32_newehdr.c"
    "${library_root}/libelf/elf64_newehdr.c"
    "${library_root}/libelf/gelf_newehdr.c"
    "${library_root}/libelf/gelf_update_ehdr.c"
    "${library_root}/libelf/elf32_getphdr.c"
    "${library_root}/libelf/elf64_getphdr.c"
    "${library_root}/libelf/gelf_getphdr.c"
    "${library_root}/libelf/elf32_newphdr.c"
    "${library_root}/libelf/elf64_newphdr.c"
    "${library_root}/libelf/gelf_newphdr.c"
    "${library_root}/libelf/gelf_update_phdr.c"
    "${library_root}/libelf/elf_getarhdr.c"
    "${library_root}/libelf/elf_getarsym.c"
    "${library_root}/libelf/elf_rawfile.c"
    "${library_root}/libelf/elf_readall.c"
    "${library_root}/libelf/elf_cntl.c"
    "${library_root}/libelf/elf_getscn.c"
    "${library_root}/libelf/elf_nextscn.c"
    "${library_root}/libelf/elf_ndxscn.c"
    "${library_root}/libelf/elf_newscn.c"
    "${library_root}/libelf/elf32_getshdr.c"
    "${library_root}/libelf/elf64_getshdr.c"
    "${library_root}/libelf/gelf_getshdr.c"
    "${library_root}/libelf/gelf_update_shdr.c"
    "${library_root}/libelf/elf_strptr.c"
    "${library_root}/libelf/elf_rawdata.c"
    "${library_root}/libelf/elf_getdata.c"
    "${library_root}/libelf/elf_newdata.c"
    "${library_root}/libelf/elf_getdata_rawchunk.c"
    "${library_root}/libelf/elf_flagelf.c"
    "${library_root}/libelf/elf_flagehdr.c"
    "${library_root}/libelf/elf_flagphdr.c"
    "${library_root}/libelf/elf_flagscn.c"
    "${library_root}/libelf/elf_flagshdr.c"
    "${library_root}/libelf/elf_flagdata.c"
    "${library_root}/libelf/elf_memory.c"
    "${library_root}/libelf/elf_update.c"
    "${library_root}/libelf/elf32_updatenull.c"
    "${library_root}/libelf/elf64_updatenull.c"
    "${library_root}/libelf/elf32_updatefile.c"
    "${library_root}/libelf/elf64_updatefile.c"
    "${library_root}/libelf/gelf_getsym.c"
    "${library_root}/libelf/gelf_update_sym.c"
    "${library_root}/libelf/gelf_getversym.c"
    "${library_root}/libelf/gelf_getverneed.c"
    "${library_root}/libelf/gelf_getvernaux.c"
    "${library_root}/libelf/gelf_getverdef.c"
    "${library_root}/libelf/gelf_getverdaux.c"
    "${library_root}/libelf/gelf_getrel.c"
    "${library_root}/libelf/gelf_getrela.c"
    "${library_root}/libelf/gelf_update_rel.c"
    "${library_root}/libelf/gelf_update_rela.c"
    "${library_root}/libelf/gelf_getdyn.c"
    "${library_root}/libelf/gelf_update_dyn.c"
    "${library_root}/libelf/gelf_getmove.c"
    "${library_root}/libelf/gelf_update_move.c"
    "${library_root}/libelf/gelf_getsyminfo.c"
    "${library_root}/libelf/gelf_update_syminfo.c"
    "${library_root}/libelf/gelf_getauxv.c"
    "${library_root}/libelf/gelf_update_auxv.c"
    "${library_root}/libelf/gelf_getnote.c"
    "${library_root}/libelf/gelf_xlatetof.c"
    "${library_root}/libelf/gelf_xlatetom.c"
    "${library_root}/libelf/nlist.c"
    "${library_root}/libelf/gelf_getsymshndx.c"
    "${library_root}/libelf/gelf_update_symshndx.c"
    "${library_root}/libelf/gelf_update_versym.c"
    "${library_root}/libelf/gelf_update_verneed.c"
    "${library_root}/libelf/gelf_update_vernaux.c"
    "${library_root}/libelf/gelf_update_verdef.c"
    "${library_root}/libelf/gelf_update_verdaux.c"
    "${library_root}/libelf/elf_getphdrnum.c"
    "${library_root}/libelf/elf_getshdrnum.c"
    "${library_root}/libelf/elf_getshdrstrndx.c"
    "${library_root}/libelf/gelf_checksum.c"
    "${library_root}/libelf/elf32_checksum.c"
    "${library_root}/libelf/elf64_checksum.c"
    "${library_root}/libelf/libelf_crc32.c"
    "${library_root}/libelf/libelf_next_prime.c"
    "${library_root}/libelf/elf_clone.c"
    "${library_root}/libelf/gelf_getlib.c"
    "${library_root}/libelf/gelf_update_lib.c"
    "${library_root}/libelf/elf32_offscn.c"
    "${library_root}/libelf/elf64_offscn.c"
    "${library_root}/libelf/gelf_offscn.c"
    "${library_root}/libelf/elf_getaroff.c"
    "${library_root}/libelf/elf_gnu_hash.c"
    "${library_root}/libelf/elf_scnshndx.c"
    "${library_root}/libelf/elf32_getchdr.c"
    "${library_root}/libelf/elf64_getchdr.c"
    "${library_root}/libelf/gelf_getchdr.c"
    "${library_root}/libelf/elf_compress.c"
    "${library_root}/libelf/elf_compress_gnu.c"
  )

  add_library(thirdparty_libelf
    ${libeu_sources}
    ${libelf_sources}
  )

  target_compile_definitions(thirdparty_libelf PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    PIC
  )

  target_link_libraries(thirdparty_libelf PRIVATE
    thirdparty_c_settings
    thirdparty_zlib
  )

  target_include_directories(thirdparty_libelf PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/config/${TARGET_PROCESSOR}"
    "${library_root}/lib"
    "${library_root}/libelf"
    "${library_root}"
  )

  target_include_directories(thirdparty_libelf SYSTEM INTERFACE
    "${library_root}/libelf"
  )
endfunction()

libelfMain()
