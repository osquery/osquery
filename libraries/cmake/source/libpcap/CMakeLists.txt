# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.

function(libPcapMain)
  execute_process(COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/src/configure")
  execute_process(COMMAND "make"
                  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src/")

  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_library(thirdparty_libpcap
	"${library_root}/bpf_dump.c"
	"${library_root}/etherent.c"   
	"${library_root}/fmtutils.c"            
	"${library_root}/pcap-common.c"  
	#"${library_root}/pcap-dos.c"      
	"${library_root}/pcap-linux.c"
	#"${library_root}/pcap-nit.c"   
	#"${library_root}/pcap-rdmasniff.c"  
	#"${library_root}/pcap-snf.c"    
	#"${library_root}/pcap-usb-linux.c"
	"${library_root}/sf-pcapng.c"
	"${library_root}/bpf_filter.c"  
	"${library_root}/fad-getad.c"  
	"${library_root}/gencode.c"     
	#"${library_root}/pcap-bt-linux.c"          
	#"${library_root}/pcap-dag.c"     
	#"${library_root}/pcap-dpdk.c"     
	"${library_root}/pcap-netfilter-linux.c"  
	#"${library_root}/pcap-npf.c"   
	#"${library_root}/pcap-rpcap.c"      
	#"${library_root}/pcap-snit.c"   
	"${library_root}/rpcap-protocol.c"  
	"${library_root}/sockutils.c"
	"${library_root}/bpf_image.c"   
	"${library_root}/fad-gifc.c"   
	"${library_root}/nametoaddr.c"  
	#"${library_root}/pcap-bt-monitor-linux.c"  
	#"${library_root}/pcap-dbus.c"    
	#"${library_root}/pcap-enet.c"     
	#"${library_root}/pcap-netmap.c"           
	"${library_root}/pcap-null.c"  
	#"${library_root}/pcap-septel.c"     
	#"${library_root}/pcap-snoop.c"  
	"${library_root}/savefile.c"        
	#"${library_root}/sslutils.c"
	#"${library_root}/dlpisubs.c"    
	#"${library_root}/fad-glifc.c"  
	"${library_root}/optimize.c"    
	"${library_root}/pcap.c"
	#"${library_root}/pcap-dlpi.c"    
	#"${library_root}/pcap-libdlpi.c"  
	#"${library_root}/pcap-new.c"              
	#"${library_root}/pcap-pf.c"    
	#"${library_root}/pcap-sita.c"       
	#"${library_root}/pcap-tc.c"     
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
