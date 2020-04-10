# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libPcapMain)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  execute_process(COMMAND "${library_root}/configure" WORKING_DIRECTORY "${library_root}" OUTPUT_QUIET)
  execute_process(COMMAND "make" WORKING_DIRECTORY "${library_root}" OUTPUT_QUIET)
  add_library(thirdparty_libpcap
	"${library_root}/bpf_dump.c"
	"${library_root}/etherent.c"
	"${library_root}/fmtutils.c"
	"${library_root}/pcap-common.c"
	"${library_root}/pcap-linux.c"
	"${library_root}/sf-pcapng.c"
	"${library_root}/bpf_filter.c"
	"${library_root}/fad-getad.c"
	"${library_root}/gencode.c"
	"${library_root}/pcap-netfilter-linux.c"
	"${library_root}/rpcap-protocol.c"
	"${library_root}/sockutils.c"
	"${library_root}/bpf_image.c"
	"${library_root}/fad-gifc.c"
	"${library_root}/nametoaddr.c"
	"${library_root}/pcap-null.c"
	"${library_root}/savefile.c"
	"${library_root}/optimize.c"
	"${library_root}/pcap.c"
	"${library_root}/sf-pcap.c"
	"${library_root}/scanner.c"
	"${library_root}/grammar.c"

  )
  target_compile_definitions(thirdparty_libpcap PRIVATE
    PACKAGE_NAME=\"libpcap\"
    PACKAGE_TARNAME=\"libpcap\"
    PACKAGE_VERSION=\"1.9.1\"
    PACKAGE_STRING=\"libpcap\ 1.9.1\"
    PACKAGE_BUGREPORT=\"\"
    PACKAGE_URL=\"\"
    PACKAGE=\"libpcap\"
    VERSION=\"1.9.1\"
    HAVE_STRLCPY
  )
  target_include_directories(thirdparty_libpcap PUBLIC
     $<1:${library_root}>
  )
  target_compile_options(thirdparty_libpcap PRIVATE
    -include "${CMAKE_CURRENT_SOURCE_DIR}/config/linux/config.h"
  )

endfunction()

libPcapMain()
