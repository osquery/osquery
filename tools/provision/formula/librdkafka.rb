require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  url "https://github.com/edenhill/librdkafka/archive/v0.9.5.tar.gz"
  sha256 "dd395ffca89c9591e567366f3ad2517cee76578a10d0a16a93f990c33f553179"
  head "https://github.com/edenhill/librdkafka.git"

  depends_on "openssl"
  depends_on "pkg-config" => :build
  depends_on "lzlib"
  depends_on "lz4" => :recommended

  def install
    if OS.linux?
      ENV.append "LIBS", "-lpthread -lz -lz -lssl -lssl -lcrypto -lcrypto  -lrt"
    end
    system "./configure", "--disable-dependency-tracking",
                          "--prefix=#{prefix}",
                          "--disable-sasl"
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
