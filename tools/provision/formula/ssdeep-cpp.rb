require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class SsdeepCpp < AbstractOsqueryFormula
  desc "ssdeep C++ library"
  homepage "https://ssdeep-project.github.io/ssdeep/index.html"
  license "GPL-2.0+"
  url "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz"
  sha256 "ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "00ccb3820f19ca73e5cf553da5623d118843fad1516d5bf283eae403ae55298d" => :x86_64_linux
    sha256 "64a6e3794335f0b24813ad3b22d40ed2bb32ad8040414e59022dfeb148e0c0e1" => :sierra
  end

  def install
    append "CXXFLAGS", "-stdlib=libc++"
    system "./configure --prefix=#{prefix} --enable-static --enable-shared=no"
    system "make"
    system "make", "install"
  end
end
