require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  license "BSD-2-Clause"
  url "https://github.com/edenhill/librdkafka/archive/v0.11.0.tar.gz"
  sha256 "d4baf9a0d08767128913bb4e39d68995a95d7efa834fcf3e4f60c3156003b887"

  depends_on "openssl"
  depends_on "pkg-config" => :build
  depends_on "lzlib"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "68c1f06e021f201a9c77b4ebd631df950e8eaf3d4e8882f65b38a8d5b4f2c825" => :sierra
    sha256 "4f66dcfc34b7224fc6cdd9b951be616d2dacb42c53bd6b4f9cf56ce765262c75" => :x86_64_linux
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

  test do
    (testpath/"test.c").write <<-EOS.undent
      #include <librdkafka/rdkafka.h>

      int main (int argc, char **argv)
      {
        int partition = RD_KAFKA_PARTITION_UA; /* random */
        return 0;
      }
    EOS
    system ENV.cc, "test.c", "-L#{lib}", "-lrdkafka", "-lz", "-lpthread", "-o", "test"
    system "./test"
  end

end
