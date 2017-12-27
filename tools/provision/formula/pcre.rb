require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Pcre < AbstractOsqueryFormula
  desc "Perl compatible regular expressions library"
  homepage "http://www.pcre.org/"
  license "BSD-3-Clause"
  url "https://ftp.pcre.org/pub/pcre/pcre-8.40.tar.gz"
  mirror "https://www.mirrorservice.org/sites/downloads.sourceforge.net/p/pc/pcre/pcre/8.40/pcre-8.40.tar.bz2"
  sha256 "1d75ce90ea3f81ee080cdc04e68c9c25a9fb984861a0618be7bbf676b18eda3e"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ef2603eb9f6ad41c19b083a2d729069dbfccf3084a66d8de0088ea2b5778009f" => :sierra
    sha256 "224a7e4f71b143064dfc97dbca18eea29b257cd1f0fefb923c9bf0943f391eca" => :x86_64_linux
  end

  def install
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
end
