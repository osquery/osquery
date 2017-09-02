require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  url "https://github.com/facebook/rocksdb/archive/rocksdb-5.7.2.tar.gz"
  sha256 "31934ed4e2ab4d08eabd5f68fa625146eba371f8f588350b79e1fee7dd510bcc"
  revision 103

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d56829ad4f656aabde556bbc3e947ebcdab3b8ca51fe4a0ab7a80cb852e10500" => :sierra
    sha256 "c27a534f2a44bec1fd4ace5040a06b66be9fbded6e3915d9baee75ac13ee841e" => :x86_64_linux
  end

  needs :cxx11

  # Remove the logic to auto-discover support for snappy and lz4.
  patch :DATA

  def install
    ENV.cxx11

    ENV["PORTABLE"] = "1"
    ENV["LIBNAME"] = "librocksdb_lite"
    ENV.append_to_cflags "-DROCKSDB_LITE=1"

    system "make", "clean"
    system "make", "static_lib"
    system "make", "install", "INSTALL_PATH=#{prefix}"
  end
end

__END__
diff --git a/build_tools/build_detect_platform b/build_tools/build_detect_platform
index 440c6a5..1888eaa 100755
--- a/build_tools/build_detect_platform
+++ b/build_tools/build_detect_platform
@@ -216,7 +216,7 @@ EOF
       #include <snappy.h>
       int main() {}
 EOF
-    if [ "$?" = 0 ]; then
+    if [ 1 = 0 ]; then
         COMMON_FLAGS="$COMMON_FLAGS -DSNAPPY"
         PLATFORM_LDFLAGS="$PLATFORM_LDFLAGS -lsnappy"
         JAVA_LDFLAGS="$JAVA_LDFLAGS -lsnappy"
@@ -274,7 +274,7 @@ EOF
       #include <lz4hc.h>
       int main() {}
 EOF
-    if [ "$?" = 0 ]; then
+    if [ 1 = 0 ]; then
         COMMON_FLAGS="$COMMON_FLAGS -DLZ4"
         PLATFORM_LDFLAGS="$PLATFORM_LDFLAGS -llz4"
         JAVA_LDFLAGS="$JAVA_LDFLAGS -llz4"
