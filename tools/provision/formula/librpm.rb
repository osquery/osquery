require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librpm < AbstractOsqueryFormula
  desc "The RPM Package Manager (RPM) development libraries"
  homepage "http://rpm.org/"
  license "LGPL-3.0+"
  url "http://ftp.rpm.org/releases/rpm-4.14.x/rpm-4.14.1.tar.bz2"
  sha256 "43f40e2ccc3ca65bd3238f8c9f8399d4957be0878c2e83cba2746d2d0d96793b"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c07a5aaec73e509b5b2365d1eb223cf5bff456b4bc1a90700776fbb23660d532" => :sierra
    sha256 "ae19662378c5129af2dc34f6f89189a746ee68151ced438c03aa272a62049421" => :x86_64_linux
  end

  depends_on "berkeley-db"
  depends_on "popt"

  patch :DATA

  def install
    ENV.append "LDFLAGS", "-lz -liconv -llzma" if OS.mac?

    args = [
      "--disable-dependency-tracking",
      "--disable-silent-rules",
      "--with-external-db",
      "--without-selinux",
      "--without-lua",
      "--without-cap",
      "--without-archive",
      "--disable-nls",
      "--disable-rpath",
      "--disable-plugins",
      "--disable-shared",
      "--disable-python",
      "--enable-static",
      "--enable-zstd=no",
      "--with-crypto=openssl",
    ]

    inreplace "Makefile.in", "rpm2cpio.$(OBJEXT)", "rpm2cpio.$(OBJEXT) lib/poptALL.$(OBJEXT) lib/poptQV.$(OBJEXT)" if OS.mac?
    inreplace "Makefile.in", "rpmspec-rpmspec.$(OBJEXT)", "rpmspec-rpmspec.$(OBJEXT) lib/poptQV.$(OBJEXT)" if OS.mac?

    system "./configure", "--prefix=#{prefix}", *args
    system "make"
    system "make", "install"
  end
end

__END__
diff --git a/rpmio/digest_openssl.c b/rpmio/digest_openssl.c
index 18e52a7..07647f2 100644
--- a/rpmio/digest_openssl.c
+++ b/rpmio/digest_openssl.c
@@ -175,9 +175,6 @@ static const EVP_MD *getEVPMD(int hashalgo)
     case PGPHASHALGO_RIPEMD160:
         return EVP_ripemd160();
 
-    case PGPHASHALGO_MD2:
-        return EVP_md2();
-
     case PGPHASHALGO_SHA256:
         return EVP_sha256();

diff --git a/rpmio/rpmio.c b/rpmio/rpmio.c
index c7cbc32..425d982 100644
--- a/rpmio/rpmio.c
+++ b/rpmio/rpmio.c
@@ -725,7 +725,6 @@ static const FDIO_t bzdio = &bzdio_s ;
 #include <lzma.h>
 /* Multithreading support in stable API since xz 5.2.0 */
 #if LZMA_VERSION >= 50020002
-#define HAVE_LZMA_MT
 #endif
 
 #define kBufferSize (1 << 15)
