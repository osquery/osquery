require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Popt < AbstractOsqueryFormula
  desc "Library like getopt(3) with a number of enhancements"
  homepage "http://rpm5.org"
  url "http://rpm5.org/files/popt/popt-1.16.tar.gz"
  sha256 "e728ed296fe9f069a0e005003c3d6b2dde3d9cad453422a10d6558616d304cc8"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "038a8f25463cfd002d734dd2ddcfbc564373f35237fcc499f98638d9f3f75345" => :x86_64_linux
  end

  option :universal

  def install
    ENV.universal_binary if build.universal?
    system "./configure", "--disable-debug", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
