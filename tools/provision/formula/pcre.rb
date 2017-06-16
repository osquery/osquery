require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Pcre < AbstractOsqueryFormula
  desc "Perl compatible regular expressions library"
  homepage "http://www.pcre.org/"
  url "https://ftp.pcre.org/pub/pcre/pcre-8.40.tar.gz"
  mirror "https://www.mirrorservice.org/sites/downloads.sourceforge.net/p/pc/pcre/pcre/8.40/pcre-8.40.tar.bz2"
  sha256 "1d75ce90ea3f81ee080cdc04e68c9c25a9fb984861a0618be7bbf676b18eda3e"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ac3137371bd766d83c3a99c165c8c2b0d5dc249b097650f4006c0ca63fc033d6" => :sierra
    sha256 "65248970cef381a2b511c68004ae5344713bd4fa5fd22c70d06f789efd33586c" => :x86_64_linux
  end

  head do
    url "svn://vcs.exim.org/pcre/code/trunk"

    depends_on "automake" => :build
    depends_on "autoconf" => :build
    depends_on "libtool" => :build
  end

  option "without-check", "Skip build-time tests (not recommended)"
  option :universal

  fails_with :llvm do
    build 2326
    cause "Bus error in ld on SL 10.6.4"
  end

  depends_on "bzip2" unless OS.mac?
  depends_on "zlib" unless OS.mac?

  def install
    ENV.universal_binary if build.universal?

    system "./autogen.sh" if build.head?
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--enable-utf8",
                          "--enable-pcre8",
                          "--enable-pcre16",
                          "--enable-pcre32",
                          "--enable-unicode-properties",
                          "--enable-pcregrep-libz",
                          "--enable-pcregrep-libbz2",
                          "--enable-jit",
                          "--disable-shared",
                          "--enable-static"
    system "make"
    ENV.deparallelize
    system "make", "install"
  end

  test do
    system "#{bin}/pcregrep", "regular expression", "#{prefix}/README"
  end
end
