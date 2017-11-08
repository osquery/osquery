require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Augeas < AbstractOsqueryFormula
  desc "A configuration editing tool and API"
  homepage "http://augeas.net/"
  url "https://github.com/hercules-team/augeas.git",
    :revision => "3775c2bf53fef5f694fcf25308cee1dfe00600c4"
  version "1.9.0"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "3e09566342fbb532676db198d8c3b5c5bacdb3bc633dd751f19ac2a3b184631c" => :sierra
    sha256 "38b142641d71776eda481341e4e5d1b7396f30ae9266801416fa6129fcb01c15" => :x86_64_linux
  end

  # The autoconfigure requests readline.
  # We avoid compiling the augeas tooling, thus do not need readline.
  patch :DATA

  def install
    ENV.append_to_cflags "-I/usr/include/libxml2" if OS.mac?
    system "./autogen.sh", "--without-selinux", "--prefix=#{prefix}"

    args = [
      "--without-selinux",
      "--prefix=#{prefix}",
      "--disable-dependency-tracking",
      "--enable-shared=no"
    ]
    system "./configure", *args

    # Build the local gnulib checkout.
    cd "gnulib/lib" do
      system "make"
    end

    # Skip building augtool and augparse to avoid readline requirements.
    cd "src" do
      system "make", "datadir.h"
      system "make", "install-libLTLIBRARIES"
      system "make", "install-data-am"
    end

    # Install the lenses on the build machine.
    system "make", "install-data-am"
  end
end
__END__
diff --git a/configure.ac b/configure.ac
index 5230efe..d639e14 100644
--- a/configure.ac
+++ b/configure.ac
@@ -91,7 +91,7 @@ AUGEAS_COMPILE_WARNINGS(maximum)
 AUGEAS_CFLAGS=-std=gnu99
 AC_SUBST(AUGEAS_CFLAGS)

-AUGEAS_CHECK_READLINE
+# AUGEAS_CHECK_READLINE
 AC_CHECK_FUNCS([open_memstream uselocale])

 AC_MSG_CHECKING([how to pass version script to the linker ($LD)])
