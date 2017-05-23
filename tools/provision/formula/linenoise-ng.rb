require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LinenoiseNg < AbstractOsqueryFormula
  desc "A small self-contained alternative to readline and libedit"
  homepage "https://github.com/arangodb/linenoise-ng"
  url "https://github.com/theopolis/linenoise-ng/archive/v1.0.1.tar.gz"
  sha256 "c317f3ec92dcb4244cb62f6fb3b7a0a5a53729a85842225fcfce0d4a429a0dfa"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "ab006b71758c28c8d08621aabab61086150f03ff6e147a9f942317f38c7ac25e" => :sierra
    sha256 "6aecbd0d97b3973d0e7fb5d6859ec985c6ee9da862fe22ffd13e0cfb738cb2f4" => :x86_64_linux
  end

  def install
    mkdir "build"
    cd "build" do
      args = osquery_cmake_args
      args += [
        "-DCMAKE_CXX_FLAGS=#{ENV["CXXFLAGS"]}"
      ]

      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end
end
