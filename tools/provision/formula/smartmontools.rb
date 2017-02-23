require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.2.5.tar.gz"
  sha256 "b211af0c8bec399ccd50a14962ba0c63c2ad26be91eda02978c97ce30976172b"


  depends_on "automake" => :build
  depends_on "autoconf" => :build
  depends_on "libtool" => :build

  def install
    system "./autogen.sh"

    ENV.append "CXXFLAGS", "-fPIC"
    system "./configure", "--prefix=#{prefix}"
    system "make", "install"
  end
end
