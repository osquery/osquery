require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Bzip2 < AbstractOsqueryFormula
  desc "Freely available high-quality data compressor"
  homepage "http://www.bzip.org/"
  license "bzip2-1.0.6"
  url "http://www.bzip.org/1.0.6/bzip2-1.0.6.tar.gz"
  sha256 "a2848f34fcd5d6cf47def00461fcb528a0484d8edef8208d6d2e2909dc61d9cd"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9198241b2295595a07f0471c560d89afede570550b9d1b7fde1137fd9655273a" => :x86_64_linux
  end

  keg_only :provided_by_osx

  def install
    inreplace "Makefile", "$(PREFIX)/man", "$(PREFIX)/share/man"
    # Expect -fPIC for static library.
    inreplace "Makefile", "CFLAGS=", "CFLAGS=#{ENV.cflags} "
    inreplace "Makefile", "CC=gcc", "CC=#{ENV["CC"]} "

    system "make", "install", "PREFIX=#{prefix}"
  end
end
