require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libxml2 < AbstractOsqueryFormula
  desc "GNOME XML library"
  homepage "http://xmlsoft.org"
  license "MIT"
  url "http://xmlsoft.org/sources/libxml2-2.9.5.tar.gz"
  mirror "ftp://xmlsoft.org/libxml2/libxml2-2.9.5.tar.gz"
  sha256 "4031c1ecee9ce7ba4f313e91ef6284164885cdb69937a123f6a83bb6a72dcd38"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "19363b22cf72a3b7371e21c7da40f4523977bfd4599ed71f547f1dfbed960695" => :sierra
    sha256 "af20f230a00b4bcc59361e99fa51c2278a448f7b50b256af31ac3e48c2187e9f" => :x86_64_linux
  end

  def install
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
