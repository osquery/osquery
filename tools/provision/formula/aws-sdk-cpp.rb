require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class AwsSdkCpp < AbstractOsqueryFormula
  desc "AWS SDK for C++"
  homepage "https://github.com/aws/aws-sdk-cpp"
  license "Apache-2.0"
  url "https://github.com/aws/aws-sdk-cpp/archive/1.2.7.tar.gz"
  sha256 "1f65e63dbbceb1e8ffb19851a8e0ee153e05bf63bfa12b0e259d50021ac3ab6e"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b35c6889799abe5553b428cd300622fc443a6aae8db9114cdc6172bafd2f902a" => :sierra
    sha256 "afa67a91ae0356516861e677ac6b64f91d848fdc3ae10374934188ac9c70863c" => :x86_64_linux
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
end
