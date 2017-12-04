require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  license "Apache-2.0"
  url "https://github.com/aws/aws-sdk-cpp/archive/1.2.7.tar.gz"
  sha256 "1f65e63dbbceb1e8ffb19851a8e0ee153e05bf63bfa12b0e259d50021ac3ab6e"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "7ee648587946bee53a22e12c391b3176bc48c5a9b5a7ae6bb7fad158bbe9adc6" => :sierra
    sha256 "900b4f5ed5c5b6dbbeae72e939a5d2fcd4fbdf889d6fa316eb9b5d96afe91db5" => :x86_64_linux
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
