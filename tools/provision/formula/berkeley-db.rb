require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class BerkeleyDb < AbstractOsqueryFormula
  desc "High performance key/value database"
  homepage "https://www.oracle.com/technology/products/berkeley-db/index.html"
  url "http://download.oracle.com/berkeley-db/db-6.1.26.tar.gz"
  sha256 "dd1417af5443f326ee3998e40986c3c60e2a7cfb5bfa25177ef7cadb2afb13a6"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "564398bbad9afe8c0f60c2c5ae2c592eab4a390fc096bac135f6b1d70c53319d" => :sierra
    sha256 "0c4225add337be64c394d2f777329f25a1f4eb6bb59546eaddaee25cbf8f8f75" => :x86_64_linux
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
      --disable-shared
      --enable-static
    ]
    args << "--enable-java" if build.with? "java"
    args << "--enable-sql" if build.with? "sql"

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
