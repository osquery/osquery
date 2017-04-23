require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Boost < AbstractOsqueryFormula
  desc "Collection of portable C++ source libraries"
  homepage "https://www.boost.org/"
  url "https://downloads.sourceforge.net/project/boost/boost/1.64.0/boost_1_64_0.tar.bz2"
  sha256 "7bcc5caace97baa948931d712ea5f37038dbb1c5d89b43ad4def4ed7cb683332"
  head "https://github.com/boostorg/boost.git"

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "19317b7d4ec628ebfed8f88aa3e7a18322fcf851db9e60a4deeaab28ab45a599" => :sierra
    sha256 "f6f3b08ada4648e5b3d210767323025dcd3616087fac1d0accd2b7b4cf3a45e0" => :x86_64_linux
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

    # Force boost to compile with the desired compiler
    open("user-config.jam", "a") do |file|
      if OS.mac?
        file.write "using darwin : : #{ENV.cxx} ;\n"
      else
        file.write "using gcc : : #{ENV.cxx} ;\n"
      end
    end

    # libdir should be set by --prefix but isn't
    bootstrap_args = [
      "--prefix=#{prefix}",
      "--libdir=#{lib}",
    ]

    # layout should be synchronized with boost-python
    args = [
      "--prefix=#{prefix}",
      "--libdir=#{lib}",
      "-d2",
      "-j#{ENV.make_jobs}",
      "--layout=tagged",
      "--ignore-site-config",
      "--user-config=user-config.jam",
      "--disable-icu",
      "--with-filesystem",
      "--with-regex",
      "--with-system",
      "--with-thread",
      "--with-coroutine2",
      "--with-context",
      "threading=multi",
      "link=static",
      "optimization=space",
      "variant=release",
    ]

    # Trunk starts using "clang++ -x c" to select C compiler which breaks C++11
    # handling using ENV.cxx11. Using "cxxflags" and "linkflags" still works.
    if build.cxx11? or true
      args << "cxxflags=-std=c++11 -fpic"
      #if ENV.compiler == :clang and OS.mac?
      #  #args << "cxxflags=-stdlib=libc++" << "linkflags=-stdlib=libc++"
      #end
    end

    # Fix error: bzlib.h: No such file or directory
    # and /usr/bin/ld: cannot find -lbz2
    args += [
      "include=#{HOMEBREW_PREFIX}/include",
      "linkflags=-L#{HOMEBREW_PREFIX}/lib"] unless OS.mac?

    system "./bootstrap.sh", *bootstrap_args
    system "./b2", "headers"
    system "./b2", "install", *args
  end
end
