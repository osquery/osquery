require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libtar < AbstractOsqueryFormula
  desc "C library for manipulating POSIX tar files"
  homepage "http://repo.or.cz/w/libtar.git"
  url "http://repo.or.cz/libtar.git",
      :tag => "v1.2.20",
      :revision => "0907a9034eaf2a57e8e4a9439f793f3f05d446cd"

  depends_on "autoconf" => :build
  depends_on "automake" => :build
  depends_on "libtool" => :build

  def install
    system "autoreconf", "--force", "--install"
    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--mandir=#{man}"
    system "make", "install"
  end

  test do
    (testpath/"homebrew.txt").write "This is a simple example"
    system "tar", "-cvf", "test.tar", "homebrew.txt"
    rm "homebrew.txt"
    assert !File.exist?("homebrew.txt")
    assert File.exist?("test.tar")

    system bin/"libtar", "-x", "test.tar"
    assert File.exist?("homebrew.txt")
  end
end
