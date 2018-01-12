require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Librdkafka < AbstractOsqueryFormula
  desc "The Apache Kafka C/C++ library"
  homepage "https://github.com/edenhill/librdkafka"
  license "BSD-2-Clause"
  url "https://github.com/edenhill/librdkafka/archive/v0.11.3.tar.gz"
  sha256 "2b96d7ed71470b0d0027bd9f0b6eb8fb68ed979f8092611c148771eb01abb72c"
  revision 200

  depends_on "openssl"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "01894340a1b04fdf2a8858a75ffc2025ef621792d3e1c66c5b5d3143e0e7b975" => :sierra
    sha256 "f366a7b46d6f0c3141a64c059ec03d8d2f5880eb08317ae712747e775e05f914" => :x86_64_linux
  end

  # Do not use clock_gettime on macOS (introduced in 10.12).
  patch :DATA

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

__END__
diff --git a/src/tinycthread.c b/src/tinycthread.c
index 0049db3..9b186a3 100644
--- a/src/tinycthread.c
+++ b/src/tinycthread.c
@@ -921,7 +921,7 @@ int _tthread_timespec_get(struct timespec *ts, int base)
 {
 #if defined(_TTHREAD_WIN32_)
   struct _timeb tb;
-#elif !defined(CLOCK_REALTIME)
+#elif !defined(CLOCK_REALTIME) || defined(__APPLE__)
   struct timeval tv;
 #endif
 
@@ -934,7 +934,7 @@ int _tthread_timespec_get(struct timespec *ts, int base)
   _ftime_s(&tb);
   ts->tv_sec = (time_t)tb.time;
   ts->tv_nsec = 1000000L * (long)tb.millitm;
-#elif defined(CLOCK_REALTIME)
+#elif defined(CLOCK_REALTIME) && !defined(__APPLE__)
   base = (clock_gettime(CLOCK_REALTIME, ts) == 0) ? base : 0;
 #else
   gettimeofday(&tv, NULL);
