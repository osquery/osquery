require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gflags < AbstractOsqueryFormula
  desc "Library for processing command-line flags"
  homepage "https://gflags.github.io/gflags/"
  url "https://github.com/gflags/gflags/archive/v2.2.0.tar.gz"
  sha256 "466c36c6508a451734e4f4d76825cf9cd9b8716d2b70ef36479ae40f08271f88"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "d5528bd0004861e969d6a5097042bc6437dd99c2b86f0176e158e93d218ecd0a" => :sierra
    sha256 "3791fb55f49adafab0fd15a32060f0dd70609e021a2447f6cd0444406c744929" => :x86_64_linux
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
