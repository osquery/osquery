require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class BerkeleyDb < AbstractOsqueryFormula
  desc "High performance key/value database"
  homepage "https://www.oracle.com/technology/products/berkeley-db/index.html"
  license "Sleepycat"
  url "http://pkgs.fedoraproject.org/repo/pkgs/libdb/db-5.3.28.tar.gz/b99454564d5b4479750567031d66fe24/db-5.3.28.tar.gz"
  sha256 "e0a992d740709892e81f9d93f06daf305cf73fb81b545afe72478043172c3628"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "6088259904f7633200facfc9953ea974f67ec7f7a823c646590819085abfe2b8" => :sierra
    sha256 "eeafab9caee4cd85d5220f28497955c629af669442396770a583c99eff033db9" => :x86_64_linux
  end

  def install
    # BerkeleyDB dislikes parallel builds
    ENV.deparallelize
    # --enable-compat185 is necessary because our build shadows
    # the system berkeley db 1.x
    args = %W[
      --disable-debug
      --prefix=#{prefix}
      --mandir=#{man}
      --enable-cxx
      --enable-compat185
      --disable-shared
      --enable-static
    ]

    inreplace "src/dbinc/atomic.h", "__atomic_compare_exchange", "__atomic_compare_exchange_db"
    inreplace [
      "src/dbinc/atomic.h",
      "src/mutex/mut_tas.c",
      "src/mp/mp_fget.c",
      "src/mp/mp_mvcc.c",
      "src/mp/mp_region.c"
    ], "atomic_init", "atomic_init_db"

    # BerkeleyDB requires you to build everything from the build_unix subdirectory
    cd "build_unix" do
      system "../dist/configure", *args
      system "make", "install"

      # use the standard docs location
      # doc.parent.mkpath
      # mv prefix/"docs", doc
      rm_rf prefix/"docs"
    end
  end
end
