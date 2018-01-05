require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gflags < AbstractOsqueryFormula
  desc "Library for processing command-line flags"
  homepage "https://gflags.github.io/gflags/"
  license "MIT"
  url "https://github.com/gflags/gflags/archive/v2.2.1.tar.gz"
  sha256 "ae27cdbcd6a2f935baa78e4f21f675649271634c092b1be01469440495609d0e"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "dd8f29f2e3f51f8ab9071172cdfdb4dfbd0f65c7e56324469901620aa515041e" => :sierra
    sha256 "207abb23d835c159094abcb723add137fafd19edcc34079b75aa1ca50ff050ee" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DBUILD_SHARED_LIBS=OFF"

    mkdir "buildroot" do
      system "cmake", "..", *args
      system "make", "install"
    end
  end
end
