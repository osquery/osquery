require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Glog < AbstractOsqueryFormula
  desc "Application-level logging library"
  homepage "https://github.com/google/glog"
  url "https://github.com/google/glog/archive/v0.3.4.tar.gz"
  sha256 "ce99d58dce74458f7656a68935d7a0c048fa7b4626566a71b7f4e545920ceb10"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d268354a25c56e1e5c653cb0ce0f5d4ed00213484fa969eea1fab03d765814c9" => :el_capitan
    sha256 "f432478f58c504eaa69caf1c37461d478086e57b2d396c2d8c83e687425255c3" => :x86_64_linux
  end

  depends_on "gflags"

  def install
    ENV.cxx11

    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}"
    system "make", "install"
  end
end
