require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  license "BSD-2-Clause"
  url "https://github.com/edenhill/librdkafka/archive/v0.11.1.tar.gz"
  sha256 "dd035d57c8f19b0b612dd6eefe6e5eebad76f506e302cccb7c2066f25a83585e"
  revision 200

  depends_on "openssl"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "26704f9e73096866a8331653a004725e32a61d166ddcb486bc20c1d6e4c15e6f" => :sierra
    sha256 "399d36524c08032e79b0d3f9673e6be4bc5f1c20c1e0dcff91316e9966465d68" => :x86_64_linux
  end

  def install
    args = [
      "--disable-dependency-tracking",
      "--prefix=#{prefix}",
      "--disable-sasl",
      "--disable-lz4",
    ]

    if OS.linux?
      ENV.append "LIBS", "-lpthread -lz -lssl -lcrypto -lrt"
    end

    system "./configure", *args
    system "make"
    system "make", "install"
  end
end
