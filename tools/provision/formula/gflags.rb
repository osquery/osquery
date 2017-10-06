require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gflags < AbstractOsqueryFormula
  desc "Library for processing command-line flags"
  homepage "https://gflags.github.io/gflags/"
  url "https://github.com/gflags/gflags/archive/v2.2.1.tar.gz"
  sha256 "ae27cdbcd6a2f935baa78e4f21f675649271634c092b1be01469440495609d0e"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "7dcbcafe75a7ea73b5e558e83f78b0d2ce8a194b9cdc92d2860ec465396b7020" => :sierra
    sha256 "3a7723739d6b7280dfb36e030b15ec75669e95e041596cb6e9f387cd7e3858e4" => :x86_64_linux
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
