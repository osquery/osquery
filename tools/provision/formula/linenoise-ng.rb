require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LinenoiseNg < AbstractOsqueryFormula
  desc "A small self-contained alternative to readline and libedit"
  homepage "https://github.com/arangodb/linenoise-ng"
  url "https://github.com/theopolis/linenoise-ng/archive/v1.0.1.tar.gz"
  sha256 "c317f3ec92dcb4244cb62f6fb3b7a0a5a53729a85842225fcfce0d4a429a0dfa"
  revision 2

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "94ad589501fb7d118dfab673b8e45d268d726175243b2a205ad5eca446c9352e" => :sierra
  end

  def install
    mkdir "build"
    cd "build" do
      args = std_cmake_args
      args += [
        "-DCMAKE_CXX_FLAGS=-mno-avx -fPIC"
      ]

      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end
end
