require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  url "https://github.com/aws/aws-sdk-cpp/archive/0.14.4.tar.gz"
  sha256 "2e935275c6f7eb25e7d850b354344c92cacb7c193b708ec64ffce10ec6afa7f4"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "0b9d7b11f5c6e7cf7de5b20c5cc19bb2e4f844df4afa00a535d648b99ef3a747" => :sierra
    sha256 "4a46a467ea1a8e1bd4c10b42dfe30055f6d3eb0bddee4f64c108a7ca780915ce" => :el_capitan
    sha256 "99c11985fc79446a442055eae1c1eecdf14d33434f40df91bd99f97c0b7dadce" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    inreplace "CMakeLists.txt", "${CMAKE_CXX_FLAGS_RELEASE} -s", "${CMAKE_CXX_FLAGS_RELEASE}"

    args = osquery_cmake_args
    args << "-DSTATIC_LINKING=1"
    args << "-DNO_HTTP_CLIENT=1"
    args << "-DMINIMIZE_SIZE=ON"
    args << "-DBUILD_SHARED_LIBS=OFF"

    args << "-DBUILD_ONLY=firehose;kinesis;sts"

    mkdir "build" do
      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end
  end

  test do
    (testpath/"test.cpp").write <<-EOS.undent
      #include <aws/core/Version.h>
      #include <iostream>

      int main() {
          std::cout << Aws::Version::GetVersionString() << std::endl;
          return 0;
      }
    EOS
    system ENV.cxx, "test.cpp", "-o", "test", "-laws-cpp-sdk-core"
    system "./test"
  end
end
