require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LinenoiseNg < AbstractOsqueryFormula
  desc "A small self-contained alternative to readline and libedit"
  homepage "https://github.com/arangodb/linenoise-ng"
  url "https://github.com/theopolis/linenoise-ng/archive/v1.0.1.tar.gz"
  sha256 "c317f3ec92dcb4244cb62f6fb3b7a0a5a53729a85842225fcfce0d4a429a0dfa"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "9df286d60a0f36010be1dbf967f888e0ca6376ce2807042e1bf055ed5a2ebc93" => :sierra
    sha256 "543c7d09ee67e59b795a4f910152fbb106be7e6bd7c1b13358ef5f810f210af7" => :x86_64_linux
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
