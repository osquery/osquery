require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class BerkeleyDb < AbstractOsqueryFormula
  desc "High performance key/value database"
  homepage "https://www.oracle.com/technology/products/berkeley-db/index.html"
  url "http://download.oracle.com/berkeley-db/db-6.1.26.tar.gz"
  sha256 "dd1417af5443f326ee3998e40986c3c60e2a7cfb5bfa25177ef7cadb2afb13a6"
  revision 1

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1b902db64ebf9a1941f1a016233c80915b936d5ea0850e41f9d116ebc7c48a0c" => :x86_64_linux
  end

  option "with-java", "Compile with Java support."
  option "with-sql", "Compile with SQL support."

  deprecated_option "enable-sql" => "with-sql"

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
    ]
    args << "--enable-java" if build.with? "java"
    args << "--enable-sql" if build.with? "sql"

    # BerkeleyDB requires you to build everything from the build_unix subdirectory
    cd "build_unix" do
      system "../dist/configure", *args
      system "make", "install"

      # use the standard docs location
      doc.parent.mkpath
      mv prefix/"docs", doc
    end
  end
end
