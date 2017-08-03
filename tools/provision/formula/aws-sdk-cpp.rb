require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  url "https://github.com/aws/aws-sdk-cpp/archive/1.1.20.tar.gz"
  sha256 "94d3bf8cbb1db18ebdb50fbf20aa48ad1838f1743bbd22ca04adbaad9bc284dc"
  revision 101

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "68a77b8250e9408bc365c43a0701ff389f39db61ee1d7f876459501236004c44" => :sierra
    sha256 "e89d2f3a6d190c2b8a02b61fa396588ec23c6fae0aad8307b1fb5d0bdeecae99" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DSTATIC_LINKING=1"
    args << "-DNO_HTTP_CLIENT=1"
    args << "-DMINIMIZE_SIZE=ON"
    args << "-DBUILD_SHARED_LIBS=OFF"

    args << "-DBUILD_ONLY=ec2;firehose;kinesis;sts"

    mkdir "build" do
      system "cmake", "..", *args
      system "make"
      system "make", "install"
    end

    # Move lib64/* to lib/ on Linuxbrew
    lib64 = Pathname.new "#{lib}64"
    if lib64.directory?
      mkdir_p lib
      system "mv #{lib64}/* #{lib}/"
      rmdir lib64
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
