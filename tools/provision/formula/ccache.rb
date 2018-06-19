require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Ccache < AbstractOsqueryFormula
  desc "Object-file caching compiler wrapper"
  homepage "https://ccache.samba.org/"
  url "https://www.samba.org/ftp/ccache/ccache-3.3.1.tar.xz"
  sha256 "c6d87a49cc6d7639636d289ed9a5f560bc2acf7ab698fe8ee14e9c9f15ba41c6"
  revision 200

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "e2cc1c707095c42674139bddbf5bc40562e3194ae7bd22bb402a096041349c67" => :sierra
    sha256 "6232d274d9cb91b394e91ceb51b63261f5e5ca3ec355afd61a346b34c846300c" => :x86_64_linux
  end

  head do
    url "https://github.com/ccache/ccache.git"

    depends_on "autoconf" => :build
    depends_on "automake" => :build
    depends_on "libtool" => :build
  end

  def install
    system "./autogen.sh" if build.head?
    system "./configure", "--prefix=#{prefix}", "--mandir=#{man}", "--with-bundled-zlib"
    system "make"
    system "make", "install"

    libexec.mkpath

    %w[
      clang
      clang++
      cc
      gcc gcc2 gcc3 gcc-3.3 gcc-4.0 gcc-4.2 gcc-4.3 gcc-4.4 gcc-4.5 gcc-4.6 gcc-4.7 gcc-4.8 gcc-4.9 gcc-5 gcc-6
      c++ c++3 c++-3.3 c++-4.0 c++-4.2 c++-4.3 c++-4.4 c++-4.5 c++-4.6 c++-4.7 c++-4.8 c++-4.9 c++-5 c++-6
      g++ g++2 g++3 g++-3.3 g++-4.0 g++-4.2 g++-4.3 g++-4.4 g++-4.5 g++-4.6 g++-4.7 g++-4.8 g++-4.9 g++-5 g++-6
    ].each do |prog|
      libexec.install_symlink "#{bin}/ccache" => prog
    end
  end

  def caveats; <<-EOS.undent
    To install symlinks for compilers that will automatically use
    ccache, prepend this directory to your PATH:
      #{opt_libexec}
    If this is an upgrade and you have previously added the symlinks to
    your PATH, you may need to modify it to the path specified above so
    it points to the current version.
    NOTE: ccache can prevent some software from compiling.
    ALSO NOTE: The brew command, by design, will never use ccache.
    EOS
  end
end
