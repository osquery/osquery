require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Broker < AbstractOsqueryFormula
  desc "Broker Communication Library"
  homepage "https://github.com/bro/broker"
  url "https://github.com/bro/broker.git", # Need git url for recursive clone
      :branch => "topic/actor-system"
      #:revision => "68a36ed81480ba935268bcaf7b6f2249d23436da"
	  #:tag => "v0.6"
  head "https://github.com/bro/broker.git"
  version "0.6"
  revision 1

  needs :cxx11

  bottle do
      root_url "https://osquery-packages.s3.amazonaws.com/bottles"
      cellar :any_skip_relocation
  end

  depends_on "caf"
  depends_on "openssl"
  depends_on "cmake" => :build

  # Use static libcaf
  patch :DATA

  def install
    #prepend "CXXFLAGS", "-std=c++11 -stdlib=libstdc++ -Wextra -Wall -ftemplate-depth=512 -pedantic"
    prepend "CXXFLAGS", "-std=c++11 -Wextra -Wall"
    args = %W[--prefix=#{prefix} --enable-static-only --with-caf=#{default_prefix}]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/cmake/FindCAF.cmake b/cmake/FindCAF.cmake
index ea2860c..845a6e7 100644
--- a/cmake/FindCAF.cmake
+++ b/cmake/FindCAF.cmake
@@ -39,6 +39,11 @@ foreach (comp ${CAF_FIND_COMPONENTS})
               ${HDRNAME}
             HINTS
               ${header_hints}
+            NO_DEFAULT_PATH)
+  find_path(CAF_INCLUDE_DIR_${UPPERCOMP}
+            NAMES
+              ${HDRNAME}
+            HINTS
               /usr/include
               /usr/local/include
               /opt/local/include
@@ -67,9 +72,14 @@ foreach (comp ${CAF_FIND_COMPONENTS})
       endif ()
       find_library(CAF_LIBRARY_${UPPERCOMP}
                    NAMES
-                     "caf_${comp}"
+                     "caf_${comp}_static"
                    HINTS
                      ${library_hints}
+                   NO_DEFAULT_PATH)
+       find_library(CAF_LIBRARY_${UPPERCOMP}
+                   NAMES
+                     "caf_${comp}_static"
+                   HINTS
                      /usr/lib
                      /usr/local/lib
                      /opt/local/lib
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 48717a4..42e0828 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -31,6 +31,9 @@ endif ()
 include_directories(BEFORE ${CAF_INCLUDE_DIRS})
 set(LINK_LIBS ${LINK_LIBS} ${CAF_LIBRARIES})

+find_package(OpenSSL REQUIRED)
+set(LINK_LIBS ${LINK_LIBS} ${OPENSSL_LIBRARIES})
+
 # RocksDB
 find_package(RocksDB)
 if (ROCKSDB_FOUND)
