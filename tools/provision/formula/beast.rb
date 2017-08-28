require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Beast < AbstractOsqueryFormula
  desc "HTTP and WebSocket built on Boost.Asio in C++11"
  homepage "http://vinniefalco.github.io/"
  head "https://github.com/vinniefalco/Beast.git"
  url "https://github.com/uptycs-nishant/Beast/archive/v84.zip"
  version "BETA"

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
