require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gflags < AbstractOsqueryFormula
  desc "Library for processing command-line flags"
  homepage "https://gflags.github.io/gflags/"
  url "https://github.com/gflags/gflags/archive/v2.2.0.tar.gz"
  sha256 "466c36c6508a451734e4f4d76825cf9cd9b8716d2b70ef36479ae40f08271f88"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b1f631a81f19deb2f9d09050e4ca59c2d7b0ed389a5fb1ce178bae1d1325de00" => :sierra
    sha256 "2ef16484fd377d1e0ade7c4261cf8c9099cb12350ca7145862aa61f32b4ce67f" => :x86_64_linux
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
