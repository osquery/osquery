require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Gflags < AbstractOsqueryFormula
  desc "Library for processing command-line flags"
  homepage "https://gflags.github.io/gflags/"
  url "https://github.com/gflags/gflags/archive/v2.2.0.tar.gz"
  sha256 "466c36c6508a451734e4f4d76825cf9cd9b8716d2b70ef36479ae40f08271f88"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "478baa80b373c27fd573b68b9f0e1bfb9fc5376997ce1aafd750bbb06d9056b1" => :sierra
    sha256 "1770ef053f031ceb8987cb2bdd7f99e784752aba5a7a5948998dacb144d9908b" => :el_capitan
    sha256 "bdc41e050721865cc5b2b72152a4229e2f83bbb7cb4f03c3d636c43cbc0aba73" => :x86_64_linux
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
