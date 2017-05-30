require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libxml2 < AbstractOsqueryFormula
  desc "GNOME XML library"
  homepage "http://xmlsoft.org"
  url "http://xmlsoft.org/sources/libxml2-2.9.4.tar.gz"
  mirror "ftp://xmlsoft.org/libxml2/libxml2-2.9.4.tar.gz"
  sha256 "ffb911191e509b966deb55de705387f14156e1a56b21824357cdf0053233633c"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "73f8b62e310889441ff1f3ae2515fb3a6a2cac493f04489afd062d1c8ca5e48c" => :sierra
    sha256 "779b194af3e967606fc801babdbe4e3454d2803ebce77eaa14d370b13245c05c" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?

    if build.head?
      inreplace "autogen.sh", "libtoolize", "glibtoolize"
      system "./autogen.sh"
    end

    args = []
    args << "--with-zlib=#{legacy_prefix}" if OS.linux?
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--without-python",
                          "--without-lzma",
                          "--enable-static",
                          "--disable-shared",
                          *args
    system "make"
    ENV.deparallelize
    system "make", "install"
    ln_sf prefix/"include/libxml2/libxml", prefix/"include/libxml"
  end
end
