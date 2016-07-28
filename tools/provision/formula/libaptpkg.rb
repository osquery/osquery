require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Libaptpkg < AbstractOsqueryFormula
  desc "The low-level bindings for apt-pkg"
  homepage "https://apt.alioth.debian.org/python-apt-doc/library/apt_pkg.html"
  url "https://osquery-packages.s3.amazonaws.com/deps/apt-1.2.6.tar.gz"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "c8ab328fe59507a390c2c6a7f65e1fdc17b015ab81b9f5cf5873f8aa49e8a59e" => :x86_64_linux
  end

  def install
    args = []
    args << "STATICLIBS=1"

    inreplace "configure", "dpkg-architecture -qDEB_HOST_ARCH", "echo 'amd64'"

    system "make", "clean"
    system "./configure", "--prefix=#{prefix}"
    system "make", "library", *args

    # apt-pkg does not include an install target.
    mkdir_p "#{prefix}/lib"
    system "cp", "bin/libapt-pkg.a", "#{prefix}/lib/"
    mkdir_p "#{prefix}/include/apt-pkg"
    system "cp include/apt-pkg/*.h #{prefix}/include/apt-pkg/"
  end
end
