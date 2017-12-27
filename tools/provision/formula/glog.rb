require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glog < AbstractOsqueryFormula
  desc "Application-level logging library"
  homepage "https://github.com/google/glog"
  license "Apache-2.0"
  url "https://github.com/google/glog/archive/v0.3.5.tar.gz"
  sha256 "7580e408a2c0b5a89ca214739978ce6ff480b5e7d8d7698a2aa92fadc484d1e0"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "3d6875f45ed791e552c034f474a0e5bf89d6b3235323b2d077b711fbded0df86" => :sierra
    sha256 "c0ba27596c32635814720f51503ebc0b79842d72a4d945c266ffa60aabab058f" => :x86_64_linux
  end

  depends_on "gflags"

  def install
    ENV.cxx11

    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--disable-shared",
                          "--enable-static"
    system "make", "install"
  end
end
