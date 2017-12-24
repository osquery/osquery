require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Boost < AbstractOsqueryFormula
  desc "Collection of portable C++ source libraries"
  homepage "https://www.boost.org/"
  license "BSL-1.0"
  url "https://downloads.sourceforge.net/project/boost/boost/1.66.0/boost_1_66_0.tar.bz2"
  sha256 "5721818253e6a0989583192f96782c4a98eb6204965316df9f5ad75819225ca9"
  head "https://github.com/boostorg/boost.git"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "2ec00b382e342a74cf57f12955729c6e2db616afdfc3120e3d7f3d41c6a3c559" => :sierra
    sha256 "8a435ce15fbd0f0e4c10f063a0cd94cbbaa430d3a6d64b01754b1794dae75e3f" => :x86_64_linux
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
