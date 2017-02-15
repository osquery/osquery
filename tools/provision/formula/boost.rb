require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Boost < AbstractOsqueryFormula
  desc "Collection of portable C++ source libraries"
  homepage "https://www.boost.org/"
  url "https://downloads.sourceforge.net/project/boost/boost/1.60.0/boost_1_60_0.tar.bz2"
  sha256 "686affff989ac2488f79a97b9479efb9f2abae035b5ed4d8226de6857933fd3b"
  head "https://github.com/boostorg/boost.git"
  revision 1

  # Handle compile failure with boost/graph/adjacency_matrix.hpp
  # https://github.com/Homebrew/homebrew/pull/48262
  # https://svn.boost.org/trac/boost/ticket/11880
  # patch derived from https://github.com/boostorg/graph/commit/1d5f43d
  patch :DATA

  # Fix auto-pointer registration in 1.60
  # https://github.com/boostorg/python/pull/59
  # patch derived from https://github.com/boostorg/python/commit/f2c465f
  patch do
    url "https://raw.githubusercontent.com/Homebrew/patches/9e56b45/boost/boost1_60_0_python_class_metadata.diff"
    sha256 "1a470c3a2738af409f68e3301eaecd8d07f27a8965824baf8aee0adef463b844"
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "b133a4ea9b79073a66ef11722dd94ea12f07c64c51ec0216dce193af73f438e9" => :sierra
    sha256 "5d531037e8fc6760c3cd1522703dc816c1fa2ae22a4695bb9698dc359ffc16c7" => :el_capitan
    sha256 "638c0f9dbd32c9c40459d8a377dcd63406347eccdefccaf8bca344c16f5566b4" => :x86_64_linux
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

__END__
diff -Nur boost_1_60_0/boost/graph/adjacency_matrix.hpp boost_1_60_0-patched/boost/graph/adjacency_matrix.hpp
--- boost_1_60_0/boost/graph/adjacency_matrix.hpp	2015-10-23 05:50:19.000000000 -0700
+++ boost_1_60_0-patched/boost/graph/adjacency_matrix.hpp	2016-01-19 14:03:29.000000000 -0800
@@ -443,7 +443,7 @@
     // graph type. Instead, use directedS, which also provides the
     // functionality required for a Bidirectional Graph (in_edges,
     // in_degree, etc.).
-    BOOST_STATIC_ASSERT(type_traits::ice_not<(is_same<Directed, bidirectionalS>::value)>::value);
+    BOOST_STATIC_ASSERT(!(is_same<Directed, bidirectionalS>::value));

     typedef typename mpl::if_<is_directed,
                                     bidirectional_tag, undirected_tag>::type
