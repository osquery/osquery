require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Beast < AbstractOsqueryFormula
  desc "HTTP and WebSocket built on Boost.Asio in C++11"
  homepage "http://vinniefalco.github.io/"
  head "https://github.com/boostorg/beast.git"
  url "https://github.com/boostorg/beast/archive/master.zip"
  sha256 "fd9683549da1d00dd1b1d9b9799952626e2ea7122a54563bf01d85ca74552ed7"
  version "108"

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
