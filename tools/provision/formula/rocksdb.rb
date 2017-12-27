require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Rocksdb < AbstractOsqueryFormula
  desc "Persistent key-value store for fast storage environments"
  homepage "http://rocksdb.org"
  license "Apache-2.0 and GPL-2.0+"
  url "https://github.com/facebook/rocksdb/archive/rocksdb-5.7.2.tar.gz"
  sha256 "31934ed4e2ab4d08eabd5f68fa625146eba371f8f588350b79e1fee7dd510bcc"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "5e5bb77b1ecb6d462865786993b2d64b0fe45506e983ed3258f2f7e97f82b2be" => :sierra
    sha256 "257cb44370305fd1e19cd8ba05b3b0a103b72b8d54aa557fe9575a6c4881a8bc" => :x86_64_linux
  end

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
