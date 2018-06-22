require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class SsdeepCpp < AbstractOsqueryFormula
  desc "ssdeep C++ library"
  homepage "https://ssdeep-project.github.io/ssdeep/index.html"
  license "GPL-2.0+"
  url "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz"
  sha256 "ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313"
  revision 200

  def install
    ENV.cxx11

    system "CXXFLAGS='-stdlib=libstdc++' ./configure --prefix=#{prefix} --enable-static --enable-shared=no"
    system "make"
    system "make", "install"
  end
end
