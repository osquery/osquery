require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class Cmake < AbstractOsqueryFormula
  desc "Cross-platform make"
  homepage "https://www.cmake.org/"

  head "https://cmake.org/cmake.git"

  stable do
    url "https://cmake.org/files/v3.6/cmake-3.6.0.tar.gz"
    sha256 "fd05ed40cc40ef9ef99fac7b0ece2e0b871858a82feade48546f5d2940147670"

    # This patch fixes an incompatibility with hdf5
    # See https://gitlab.kitware.com/cmake/cmake/issues/16190
    patch do
      url "https://gitlab.kitware.com/cmake/cmake/merge_requests/34.patch"
      sha256 "6d47140ebb65c045d9eee2c363aa22e53973a54b9bcdc11ef7b622c97419999f"
    end
  end

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "1aed0253cf2b7905f273075d0f5647082ee3b5395c2b9b00110b0e4687786550" => :el_capitan
    sha256 "368ea3073878ff3b801a73cac8f233c98ba842557a88a3109fb6dca31b461dcd" => :x86_64_linux
  end

  option "without-docs", "Don't build man pages"
  option "with-completion", "Install Bash completion (Has potential problems with system bash)"

  depends_on "sphinx-doc" => :build if build.with? "docs"
  depends_on "bzip2" unless OS.mac?
  depends_on "curl" unless OS.mac?
  depends_on "libidn" unless OS.mac?

  # The `with-qt` GUI option was removed due to circular dependencies if
  # CMake is built with Qt support and Qt is built with MySQL support as MySQL uses CMake.
  # For the GUI application please instead use brew install caskroom/cask/cmake.

  def install
    # Reduce memory usage below 4 GB for Circle CI.
    ENV.deparallelize if ENV["CIRCLECI"]

    args = %W[
      --prefix=#{prefix}
      --no-system-libs
      --parallel=#{ENV.make_jobs}
      --datadir=/share/cmake
      --docdir=/share/doc/cmake
      --mandir=/share/man
    ]

    # https://github.com/Homebrew/homebrew/issues/45989
    if OS.mac? && MacOS.version <= :lion
      args << "--no-system-curl"
    end

    # osquery: build with local zlib, bzip, and curl

    if build.with? "docs"
      # There is an existing issue around OS X & Python locale setting
      # See https://bugs.python.org/issue18378#msg215215 for explanation
      ENV["LC_ALL"] = "en_US.UTF-8"
      args << "--sphinx-man" << "--sphinx-build=#{Formula["sphinx-doc"].opt_bin}/sphinx-build"
    end

    system "./bootstrap", *args
    system "make"
    system "make", "install"

    if build.with? "completion"
      cd "Auxiliary/bash-completion/" do
        bash_completion.install "ctest", "cmake", "cpack"
      end
    end

    (share/"emacs/site-lisp/cmake").install "Auxiliary/cmake-mode.el"

    rm_f pkgshare/"Modules/CPack.OSXScriptLauncher.in" unless OS.mac?
  end

  test do
    (testpath/"CMakeLists.txt").write("find_package(Ruby)")
    system "#{bin}/cmake", "."
  end
end
