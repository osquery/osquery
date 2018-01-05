require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Beecrypt < AbstractOsqueryFormula
  desc "C/C++ cryptography library"
  homepage "http://beecrypt.sourceforge.net"
  license "LGPL-2.1+"
  url "https://downloads.sourceforge.net/project/beecrypt/beecrypt/4.2.1/beecrypt-4.2.1.tar.gz"
  sha256 "286f1f56080d1a6b1d024003a5fa2158f4ff82cae0c6829d3c476a4b5898c55d"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6ac5803d7e38b93223d09fb55dc56b6db16a873e8afaa98c71aa9f696eb7e372" => :sierra
    sha256 "68d10e7f9e4141cf1610788cb3e8fee4f87ee83685f7eca78f527b7f5f2813a2" => :x86_64_linux
  end

  depends_on "libtool" => :build

  # Allow us to set architecture and environment flags.
  patch :DATA

  def install
    args = [
      "--disable-dependency-tracking",
      "--disable-openmp",
      "--without-java",
      "--without-python",
      "--without-cplusplus",
      "--with-arch=x86_64",
      "--disable-shared",
      "--enable-static"
    ]

    system "./autogen.sh"
    system "autoreconf", "--force", "--install" if OS.mac?
    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "check"
    system "make", "install"
  end
end
__END__
diff --git a/configure.ac b/configure.ac
index 2eec209..1db6184 100644
--- a/configure.ac
+++ b/configure.ac
@@ -13,12 +13,7 @@ AC_PROG_AWK
 AC_ARG_ENABLE(expert-mode, [  --enable-expert-mode      follow user-defined CFLAGS settings [[default=no]]],[
   ac_enable_expert_mode=yes
   ],[
-  if test "X$CFLAGS" != "X"; then
-    echo "enabling expert mode"
-    ac_enable_expert_mode=yes
-  else
-    ac_enable_expert_mode=no
-  fi
+  ac_enable_expert_mode=no
   ])

 AC_ARG_ENABLE(debug, [  --enable-debug          creates debugging code [[default=no]]],[
