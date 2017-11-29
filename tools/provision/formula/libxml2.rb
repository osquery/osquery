require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libxml2 < AbstractOsqueryFormula
  desc "GNOME XML library"
  homepage "http://xmlsoft.org"
  license "MIT"
  url "http://xmlsoft.org/sources/libxml2-2.9.5.tar.gz"
  mirror "ftp://xmlsoft.org/libxml2/libxml2-2.9.5.tar.gz"
  sha256 "4031c1ecee9ce7ba4f313e91ef6284164885cdb69937a123f6a83bb6a72dcd38"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "145739ead08f85fff40695ac83d615aeaae9a121d388f675f29f7330fcade892" => :sierra
    sha256 "899d898d6930c15b21e97c62091fe70640ce93b37dbe08273e6b694d33de40b9" => :x86_64_linux
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
