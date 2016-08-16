require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  url "https://github.com/aws/aws-sdk-cpp/archive/0.14.4.tar.gz"
  #sha256 "ea3e618980f41dedfc2a6b187846a2bd747d9b6d9b95f733e04bec76cbeb1a46"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "953567c55e5ca1873d80acf33408db74079b9d4dfd2cd34ac582af0543b138ee" => :el_capitan
    sha256 "bfcf604046d739a7bde2285010fdd797e844ab1b1c2ec0e6b2d66db72f97cc65" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    inreplace "CMakeLists.txt", "${CMAKE_CXX_FLAGS_RELEASE} -s", "${CMAKE_CXX_FLAGS_RELEASE}"

    args = std_cmake_args
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

    lib.install Dir[lib/"mac/Release/*"].select { |f| File.file? f } if OS.mac?
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
