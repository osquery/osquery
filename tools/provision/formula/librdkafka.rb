require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  url "https://github.com/edenhill/librdkafka/archive/v0.9.4.tar.gz"
  sha256 "5007ad20a6753f709803e72c5f2c09483dcbce0f16b94b17cf677fb3e6045907"

  head "https://github.com/edenhill/librdkafka.git"

  depends_on "pkg-config" => :build
  depends_on "lzlib"
  depends_on "openssl"
  depends_on "lz4" => :recommended

  def install
    args = [
      "--disable-dependency-tracking",
      "--prefix=#{prefix}",
      "--enable-static",
      "--disable-ssl",
    ]
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
