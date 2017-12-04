require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Popt < AbstractOsqueryFormula
  desc "Library like getopt(3) with a number of enhancements"
  homepage "http://rpm5.org"
  license "X11"
  url "http://rpm5.org/files/popt/popt-1.16.tar.gz"
  sha256 "e728ed296fe9f069a0e005003c3d6b2dde3d9cad453422a10d6558616d304cc8"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dd025386db52982536899c939b02f716274972407883b6fc733374879c7da379" => :sierra
    sha256 "7fbf8db578b714069e2301ea6eb122cedd79a23bc151f555fb4c1ee1bcd6b7d9" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?
    system "./configure", "--disable-debug",
                          "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end
end
