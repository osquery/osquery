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
    sha256 "bc53cf0242cec67e7892686ce64b1ce624e2a8b6f6f3ccc6f608b6c9c1d15a54" => :sierra
    sha256 "1f146fd08755ffdd334f5fe07ba64e703e52aa11e8a3f2faf9ad57897dfbb47c" => :x86_64_linux
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
