require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  license "Apache-2.0"
  url "https://github.com/aws/aws-sdk-cpp/archive/1.4.55.tar.gz"
  sha256 "0a70c2998d29cc4d8a4db08aac58eb196d404073f6586a136d074730317fe408"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6d047fe0f7b0710aea9366af1a4f3c637c1fcd3a2f652abaa8ffc70ef5190451" => :sierra
    sha256 "d161bd821efffe73ac6cb7e7f0cefe248981c6d3ab59be17ca2de5d7f8c4eff4" => :x86_64_linux
  end

  depends_on "cmake" => :build

  def install
    ENV.cxx11

    args = osquery_cmake_args
    args << "-DSTATIC_LINKING=1"
    args << "-DNO_HTTP_CLIENT=1"
    args << "-DMINIMIZE_SIZE=ON"
    args << "-DBUILD_SHARED_LIBS=OFF"
    args << "-DENABLE_TESTING=OFF"
    args << "-DAUTORUN_UNIT_TESTS=OFF"

    args << "-DBUILD_ONLY=ec2;firehose;kinesis;sqs;sts"

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
end
