require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class LinenoiseNg < AbstractOsqueryFormula
  desc "A small self-contained alternative to readline and libedit"
  homepage "https://github.com/arangodb/linenoise-ng"
  license "BSD-3-Clause"
  url "https://github.com/theopolis/linenoise-ng/archive/v1.0.1.tar.gz"
  sha256 "c317f3ec92dcb4244cb62f6fb3b7a0a5a53729a85842225fcfce0d4a429a0dfa"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "bbeedf38db611d654183226ad1ee61ac5cf56ed8c5038a8a632673a5595940af" => :sierra
    sha256 "446e4b9823efd0a4958143a5100cdf5fbac8860d7d3e97e54f68301bdbb92a2f" => :x86_64_linux
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
