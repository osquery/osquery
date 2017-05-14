require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glog < AbstractOsqueryFormula
  desc "Application-level logging library"
  homepage "https://github.com/google/glog"
  url "https://github.com/google/glog/archive/v0.3.4.tar.gz"
  sha256 "ce99d58dce74458f7656a68935d7a0c048fa7b4626566a71b7f4e545920ceb10"
  revision 2

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c8335cd60ca536ebcb1aade89304e46c7080d97c5a3a17d9ca17410390c8676c" => :sierra
    sha256 "225f2fbef6add3fa2168c811feed4106fcb74cf4cee51759ef2149645881f534" => :x86_64_linux
  end

  depends_on "gflags"

  def install
    ENV.cxx11

    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
