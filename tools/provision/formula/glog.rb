require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glog < AbstractOsqueryFormula
  desc "Application-level logging library"
  homepage "https://github.com/google/glog"
  url "https://github.com/google/glog/archive/v0.3.4.tar.gz"
  sha256 "ce99d58dce74458f7656a68935d7a0c048fa7b4626566a71b7f4e545920ceb10"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "0188828615cf46f9c05e0ba5464613c9811eeba0486fe21c509ec62cb96bb02d" => :sierra
    sha256 "448d73a90d5bdf68bf1de09f8848e326383ddbc112d9a2b72c20fa7b32239994" => :x86_64_linux
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
