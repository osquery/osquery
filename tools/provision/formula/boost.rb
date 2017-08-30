require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Boost < AbstractOsqueryFormula
  desc "Collection of portable C++ source libraries"
  homepage "https://www.boost.org/"
  url "https://downloads.sourceforge.net/project/boost/boost/1.65.0/boost_1_65_0.tar.bz2"
  sha256 "ea26712742e2fb079c2a566a31f3266973b76e38222b9f88b387e3c8b2f9902c"
  head "https://github.com/boostorg/boost.git"
  revision 102

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "4c0c142976220ce6c5aafe451e5a92905e68468ab0bfd937c1396aa200efea40" => :sierra
    sha256 "cbf4d81d465ab3453f9e0bb1d13babf74cf1a625782a5d1e4629a65864df42e0" => :x86_64_linux
  end

  env :userpaths

  option :universal

  # Keep this option, but force C++11.
  option :cxx11
  needs :cxx11

  depends_on "bzip2" unless OS.mac?

  def install
    ENV.cxx11
    ENV.universal_binary if build.universal?

    # libdir should be set by --prefix but isn't
    bootstrap_args = [
      "--prefix=#{prefix}",
      "--libdir=#{lib}",

      # This is a non-standard toolset, but informs the bjam build to use the
      # compile and link environment variables.
      "--with-toolset=cc",
    ]

    # layout should be synchronized with boost-python
    args = [
      "--prefix=#{prefix}",
      "--libdir=#{lib}",
      "-d2",
      "-j#{ENV.make_jobs}",
      "--layout=tagged",
      "--ignore-site-config",
      "--disable-icu",
      "--with-filesystem",
      "--with-regex",
      "--with-system",
      "--with-thread",
      "--with-coroutine",
      "--with-context",
      "threading=multi",
      "link=static",
      "optimization=space",
      "variant=release",
      "toolset=clang",
    ]

    args << "cxxflags=-std=c++11 #{ENV["CXXFLAGS"]}"

    # Fix error: bzlib.h: No such file or directory
    # and /usr/bin/ld: cannot find -lbz2
    args += [
      "include=#{HOMEBREW_PREFIX}/include",
      "linkflags=#{ENV["LDFLAGS"]}"
    ] unless OS.mac?

    system "./bootstrap.sh", *bootstrap_args

    # The B2 script will not read our user-config.
    # You will encounter: ERROR: rule "cc.init" unknown in module "toolset".
    # If the lines from project-config are moved into a --user-config b2 will
    # complain about duplicate initializations:
    #  error: duplicate initialization of clang-linux
    if OS.mac?
      inreplace "project-config.jam", "cc ;", "darwin ;"
    else
      inreplace "project-config.jam", "cc ;", "clang ;"
    end

    system "./b2", "install", *args
  end
end
