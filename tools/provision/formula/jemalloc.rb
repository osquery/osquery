class Jemalloc < Formula
  desc "malloc implementation emphasizing fragmentation avoidance"
  homepage "http://jemalloc.net/"
  url "https://github.com/jemalloc/jemalloc/releases/download/5.1.0/jemalloc-5.1.0.tar.bz2"
  sha256 "5396e61cc6103ac393136c309fae09e44d74743c86f90e266948c50f3dbb7268"

  bottle do
    cellar :any
    sha256 "aa1fa19d21dda2217c2d62c43dbee14137dfadb79551513aedb401e9ba150797" => :high_sierra
    sha256 "7df7b23de1b22db39c95cafb42517dee77c2ce569ed274c1a5ad1659ac7289a5" => :sierra
    sha256 "84ad0bc4089f342efd901d1b04478495925f98a11a98a05a6b08ac7201963f31" => :el_capitan
    sha256 "ad6ef004c3a20a63bff19cdd4974ff2bbfb9d19e98a7b84ddecb730c227c99a0" => :x86_64_linux
  end

  head do
    url "https://github.com/jemalloc/jemalloc.git", :branch => "dev"

    depends_on "autoconf" => :build
    depends_on "docbook-xsl" => :build
  end

  def install
    args = %W[
      --disable-debug
      --prefix=#{prefix}
      --with-jemalloc-prefix=
    ]

    if build.head?
      args << "--with-xslroot=#{Formula["docbook-xsl"].opt_prefix}/docbook-xsl"
      system "./autogen.sh", *args
      system "make", "dist"
    else
      system "./configure", *args
    end

    system "make"
    system "make", "check"
    system "make", "install"
  end

  test do
    (testpath/"test.c").write <<~EOS
      #include <stdlib.h>
      #include <jemalloc/jemalloc.h>

      int main(void) {

        for (size_t i = 0; i < 1000; i++) {
            // Leak some memory
            malloc(i * 100);
        }

        // Dump allocator statistics to stderr
        malloc_stats_print(NULL, NULL, NULL);
      }
    EOS
    system ENV.cc, "test.c", "-L#{lib}", "-ljemalloc", "-o", "test", ("--std=c99" unless OS.mac?)
    system "./test"
  end
end
