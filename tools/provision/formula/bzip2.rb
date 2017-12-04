require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Bzip2 < AbstractOsqueryFormula
  desc "Freely available high-quality data compressor"
  homepage "http://www.bzip.org/"
  license "bzip2-1.0.6"
  url "http://www.bzip.org/1.0.6/bzip2-1.0.6.tar.gz"
  sha256 "a2848f34fcd5d6cf47def00461fcb528a0484d8edef8208d6d2e2909dc61d9cd"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9058d838c3cd7cb3e8e3dd978849b87bc6f9013c13b34e08d0875c2b3e68ce02" => :x86_64_linux
  end

  keg_only :provided_by_osx

  def install
    inreplace "Makefile", "$(PREFIX)/man", "$(PREFIX)/share/man"
    # Expect -fPIC for static library.
    inreplace "Makefile", "CFLAGS=", "CFLAGS=#{ENV.cflags} "

    system "make", "install", "PREFIX=#{prefix}"
  end

  test do
    testfilepath = testpath + "sample_in.txt"
    zipfilepath = testpath + "sample_in.txt.bz2"

    testfilepath.write "TEST CONTENT"

    system "#{bin}/bzip2", testfilepath
    system "#{bin}/bunzip2", zipfilepath

    assert_equal "TEST CONTENT", testfilepath.read
  end
end
