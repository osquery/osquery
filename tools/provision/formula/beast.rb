require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Beast < AbstractOsqueryFormula
  desc "HTTP and WebSocket built on Boost.Asio in C++11"
  homepage "http://vinniefalco.github.io/"
  head "https://github.com/boostorg/beast.git"
  url "https://github.com/uptycs-nishant/beast/archive/v111.zip"
  sha256 "003bb33e21256530deea5b1c689128990cf0fd10a31ce2d76d4c5fd470b08c8a"
  version "111"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
  end

  depends_on "openssl"
  depends_on "cmake" => :build

  needs :cxx11

  def install
    include.install Dir["include/*"]
  end
end
