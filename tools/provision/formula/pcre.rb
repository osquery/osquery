require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Pcre < AbstractOsqueryFormula
  desc "Perl compatible regular expressions library"
  homepage "http://www.pcre.org/"
  url "https://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-8.38.tar.bz2"
  mirror "https://www.mirrorservice.org/sites/downloads.sourceforge.net/p/pc/pcre/pcre/8.38/pcre-8.38.tar.bz2"
  sha256 "b9e02d36e23024d6c02a2e5b25204b3a4fa6ade43e0a5f869f254f49535079df"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b08e622fd735f2a3701f92e529aa9ab1a10de8261c6edc8ef66a7f5b15d81ba5" => :sierra
    sha256 "d53bd23be25af381a8a5e645d90f4a83e4e5acf3111abd4e482160621cff6349" => :el_capitan
    sha256 "3d2507879303c57941fa19972dc9eed980318751725908a5f8db1ba1104ea3d6" => :x86_64_linux
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
                          "--enable-jit"
    system "make"
    ENV.deparallelize
    system "make", "install"
  end

  test do
    system "#{bin}/pcregrep", "regular expression", "#{prefix}/README"
  end
end
