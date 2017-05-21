require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class ZlibLegacy < AbstractOsqueryFormula
  desc "General-purpose lossless data-compression library"
  homepage "http://www.zlib.net/"
  url "https://github.com/madler/zlib/archive/v1.2.3.tar.gz"
  sha256 "2134178c123ea8252fd6afc9b794d9a2df480ccd030cc5db720a41883676fc2e"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "f37ddfc888ac2d3421c14f8b5ebc8aa24e114c42fb4d9951a79726257d139c59" => :x86_64_linux
  end

  option :universal

  patch :DATA

  # This package is provided for legacy headers and linking to maintain ABI
  # compatibility for the deploy-targets.
  set_legacy

  # http://zlib.net/zlib_how.html
  resource "test_artifact" do
    url "http://zlib.net/zpipe.c"
    version "20051211"
    sha256 "68140a82582ede938159630bca0fb13a93b4bf1cb2e85b08943c26242cf8f3a6"
  end

  def install
    ENV.universal_binary if build.universal?
    system "./configure", "--prefix=#{prefix}", "--shared"
    system "make"
    system "make", "install"

    mkdir_p "#{legacy_prefix}/lib/pkgconfig"
    config = Pathname.new("#{prefix}/lib/pkgconfig/zlib.pc")
    config.write <<-EOS.undent
      prefix=#{prefix}
      exec_prefix=\$\{prefix\}
      libdir=\$\{exec_prefix\}/lib
      sharedlibdir=\$\{libdir\}
      includedir=\$\{prefix\}/include

      Name: zlib
      Description: zlib compression library
      Version: #{version}

      Requires:
      Libs: -L\$\{libdir\} -L\$\{sharedlibdir\} -lz
      Cflags: -I\$\{includedir\}
    EOS
  end

  test do
    testpath.install resource("test_artifact")
    system ENV.cc, "zpipe.c", "-I#{include}", "-L#{lib}", "-lz", "-o", "zpipe"

    touch "foo.txt"
    output = ("./zpipe < foo.txt > foo.txt.z")
    system output
    assert File.exist?("foo.txt.z")
  end
end

__END__
diff --git a/configure b/configure
index d7ffdc3..d7ca2c8 100755
--- a/configure
+++ b/configure
@@ -19,6 +19,7 @@
 # an error.

 LIBS=libz.a
+LDSHAREDFLAGS="$LDFLAGS"
 LDFLAGS="-L. ${LIBS}"
 VER=`sed -n -e '/VERSION "/s/.*"\(.*\)".*/\1/p' < zlib.h`
 VER2=`sed -n -e '/VERSION "/s/.*"\([0-9]*\\.[0-9]*\)\\..*/\1/p' < zlib.h`
@@ -167,6 +168,7 @@ fi
 SHAREDLIB=${SHAREDLIB-"libz$shared_ext"}
 SHAREDLIBV=${SHAREDLIBV-"libz$shared_ext.$VER"}
 SHAREDLIBM=${SHAREDLIBM-"libz$shared_ext.$VER1"}
+LDSHARED="$LDSHARED $LDSHAREDFLAGS"

 if test $shared -eq 1; then
   echo Checking for shared library support...
