require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  license "BSD-2-Clause"
  url "https://github.com/edenhill/librdkafka/archive/v0.11.1.tar.gz"
  sha256 "dd035d57c8f19b0b612dd6eefe6e5eebad76f506e302cccb7c2066f25a83585e"

  depends_on "openssl"
  depends_on "pkg-config" => :build
  depends_on "lzlib"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "059dc732ce4cbe794a92164f451ef524c625f88be8c771a158b8d06be77bc643" => :sierra
    sha256 "3908e35ba842583f8799a51dd65255e78918e26cd80e98531f6a3debab16dd67" => :x86_64_linux
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
