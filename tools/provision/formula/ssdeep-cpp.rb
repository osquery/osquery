require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class SsdeepCpp < AbstractOsqueryFormula
  desc "ssdeep C++ library"
  homepage "https://ssdeep-project.github.io/ssdeep/index.html"
  license "GPL-2.0+"
  url "https://github.com/ssdeep-project/ssdeep/releases/download/release-2.14.1/ssdeep-2.14.1.tar.gz"
  sha256 "ff2eabc78106f009b4fb2def2d76fb0ca9e12acf624cbbfad9b3eb390d931313"
  revision 201

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "87b379ad5ac57c463644b93212a110ebd10ae6363d5a58b1b81d623ac5394cb0" => :sierra
    sha256 "adf265c3b2c3a260c48be6fd8a5bedc0a99b39e836e874abe71373c84ddd693b" => :x86_64_linux
  end

  def install
    append "CXXFLAGS", "-stdlib=libc++"
    system "./configure --prefix=#{prefix} --enable-static --enable-shared=no"
    system "make"
    system "make", "install"
  end
end
