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
  revision 4

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
    prepend "CXXFLAGS", "-std=c++11 -Wextra -Wall"
    args = %W[--prefix=#{prefix} --disable-python --disable-docs --enable-static-only --with-caf=#{default_prefix}]

    system "./configure", *args
    system "make"
    system "make", "install"
  end

end

__END__
diff --git a/cmake/FindCAF.cmake b/cmake/FindCAF.cmake
index 870137c..d261d19 100644
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
@@ -71,6 +76,11 @@ foreach (comp ${CAF_FIND_COMPONENTS})
                      "caf_${comp}_static"
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
index df3a82d..eafbb9d 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -242,7 +242,7 @@ macro(add_tool name)
     target_link_libraries(${name} ${LINK_LIBS} broker)
     add_dependencies(${name} broker)
   else()
-    target_link_libraries(${name} ${LINK_LIBS} broker_static)
+    target_link_libraries(${name} broker_static ${LINK_LIBS} ${LINK_LIBS})
     add_dependencies(${name} broker_static)
   endif()
 endmacro()
diff --git a/doc/_examples/CMakeLists.txt b/doc/_examples/CMakeLists.txt
index 663d521..6690e71 100644
--- a/doc/_examples/CMakeLists.txt
+++ b/doc/_examples/CMakeLists.txt
@@ -10,7 +10,7 @@ include_directories(${CMAKE_CURRENT_SOURCE_DIR})
 if (ENABLE_SHARED)
   set(libbroker broker)
 else ()
-  set(libbroker broker_static)
+  set(libbroker broker_static ${LINK_LIBS} ${LINK_LIBS})
 endif ()

 macro(make_example cc)
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index 7b59102..075fb97 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -28,7 +28,7 @@ set(tests
 if (ENABLE_SHARED)
   set(libbroker broker)
 else ()
-  set(libbroker broker_static)
+  set(libbroker broker_static ${LINK_LIBS} ${LINK_LIBS})
 endif ()
 add_executable(broker-test ${tests})
 target_link_libraries(broker-test ${libbroker})
