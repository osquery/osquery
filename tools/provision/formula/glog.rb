require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glog < AbstractOsqueryFormula
  desc "Application-level logging library"
  homepage "https://github.com/google/glog"
  url "https://github.com/google/glog/archive/v0.3.4.tar.gz"
  sha256 "ce99d58dce74458f7656a68935d7a0c048fa7b4626566a71b7f4e545920ceb10"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "020ea9bbbc0437cbe4aae54ace88c7ab0e7961602fd61e51ddd20d3d1e58710a" => :sierra
    sha256 "b8e1f109493fd0c8ee7deb79da248fd94eca533822c26a6e0bce1c0f69aa9400" => :x86_64_linux
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
