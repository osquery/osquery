require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Smartmontools < AbstractOsqueryFormula
  desc "SMART hard drive monitoring; Fork with smartctl exposed as a static library"
  homepage "https://www.smartmontools.org/"
  url "https://github.com/allanliu/smartmontools/archive/v0.3.0.tar.gz"
  sha256 "2bc19bc974ec7e69f474ba3e22ad847f7c270a4881d3e3ce66c57d73f07ee3b4"


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
