require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libxml2 < AbstractOsqueryFormula
  desc "GNOME XML library"
  homepage "http://xmlsoft.org"
  license "MIT"
  url "http://xmlsoft.org/sources/libxml2-2.9.7.tar.gz"
  mirror "ftp://xmlsoft.org/libxml2/libxml2-2.9.7.tar.gz"
  sha256 "f63c5e7d30362ed28b38bfa1ac6313f9a80230720b7fb6c80575eeab3ff5900c"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "78b01c23d2f2391b5c0ea9c9e52489c11a28cd85b7e14f8b7a040a471e420e0c" => :sierra
    sha256 "484eeb6ff8dab7fe909a70a2ba22747796e43cf09df3f83e122c7633c0adb5e4" => :x86_64_linux
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
