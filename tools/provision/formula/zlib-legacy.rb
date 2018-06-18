require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class ZlibLegacy < AbstractOsqueryFormula
  desc "General-purpose lossless data-compression library"
  homepage "http://www.zlib.net/"
  license "Zlib"
  url "https://github.com/madler/zlib/archive/v1.2.3.tar.gz"
  sha256 "2134178c123ea8252fd6afc9b794d9a2df480ccd030cc5db720a41883676fc2e"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "43f85be447d9c46beb938fc429aa6298bc400b8d43e965a27fb3541097e1c67a" => :x86_64_linux
  end

  patch :DATA

  # This package is provided for legacy headers and linking to maintain ABI
  # compatibility for the deploy-targets.
  set_legacy

  def install
    system "./configure", "--prefix=#{prefix}", "--shared"
    system "make"
    system "make", "install"

    mkdir_p "#{legacy_prefix}/lib/pkgconfig"
    config = Pathname.new("#{prefix}/lib/pkgconfig/zlib.pc")
    config.write <<~EOS
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
