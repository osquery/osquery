require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class GlibcLegacy < AbstractOsqueryFormula
  desc "The GNU C Library"
  homepage "https://www.gnu.org/software/libc"
  license "GPL-2.0+"
  url "ftp.gnu.org/gnu/glibc/glibc-2.13.tar.bz2"
  sha256 "0173c92a0545e6d99a46a4fbed2da00ba26556f5c6198e2f9f1631ed5318dbb2"
  revision 202

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "2a410ce99f4ce9b760a64092c4e7de7fb7b22b4ee1ad351dcffc927765e7e097" => :x86_64_linux
  end

  # Must apply patches to allow compiling with newer versions of GCC/gmake.
  # Must apply d9b965fa56350d6eea9f7f438a0714c7ffbb183f to allow compiling of
  # newer GCC (>6).
  patch :DATA

  # binutils 2.20 or later is required
  depends_on "binutils"

  # Linux kernel headers 2.6.19 or later are required
  depends_on "linux-headers"

  # This package is provided for legacy headers and linking to maintain ABI
  # compatibility for the deploy-targets.
  set_legacy

  def install
    ENV["CFLAGS"] = "-U_FORTIFY_SOURCE -fno-stack-protector -O2"

    # osquery: Remove several environment variables
    ENV.delete "LD_RUN_PATH"
    ENV.delete "LIBRARY_PATH"
    ENV.delete "CPATH"
    ENV.delete "LD_LIBRARY_PATH"
    ENV["LDFLAGS"] = "-L/usr/local/osquery/lib -no-pie"

    mkdir "build" do
      args = [
        "--disable-debug",
        "--disable-dependency-tracking",
        "--disable-silent-rules",
        "--prefix=#{prefix}",
        "--enable-obsolete-rpc",
        "--without-selinux",
        "--disable-sanity-checks",
      ] # Fix error: selinux/selinux.h: No such file or directory
      args << "--with-binutils=#{Formula["binutils"].bin}"
      args << "--with-headers=#{Formula["linux-headers"].include}"
      system "../configure", *args

      system "make" # Fix No rule to make target libdl.so.2 needed by sprof
      system "make", "install"
      prefix.install_symlink "lib" => "lib64"

      # Remove getconf with non-ASCII characters.
      rm_rf Dir["#{prefix}/libexec/getconf/POSIX_V6_LP64_OFF*"]
    end
  end

  def post_install
    # Fix permissions
    chmod 0755, [lib/"ld-#{version}.so", lib/"libc-#{version}.so"]
  end
end

__END__
diff -Nur glibc-2.12.2/configure glibc-2.12.2-patched/configure
--- glibc-2.12.2/configure  2010-12-13 02:47:26.000000000 -0800
+++ glibc-2.12.2-patched/configure  2016-07-16 01:26:38.910295069 -0700
@@ -5189,7 +5189,7 @@
   ac_prog_version=`$CC -v 2>&1 | sed -n 's/^.*version \([egcygnustpi-]*[0-9.]*\).*$/\1/p'`
   case $ac_prog_version in
     '') ac_prog_version="v. ?.??, bad"; ac_verc_fail=yes;;
-    3.4* | 4.[0-9]* )
+    3.4* | 4.[0-9]* | 5.[0-9]* | 6.[0-9]* | 7.[0-9]* )
        ac_prog_version="$ac_prog_version, ok"; ac_verc_fail=no;;
     *) ac_prog_version="$ac_prog_version, bad"; ac_verc_fail=yes;;

@@ -5252,7 +5252,7 @@
   ac_prog_version=`$MAKE --version 2>&1 | sed -n 's/^.*GNU Make[^0-9]*\([0-9][0-9.]*\).*$/\1/p'`
   case $ac_prog_version in
     '') ac_prog_version="v. ?.??, bad"; ac_verc_fail=yes;;
-    3.79* | 3.[89]*)
+    3.79* | 3.[89]* | 4.[0-9]* )
        ac_prog_version="$ac_prog_version, ok"; ac_verc_fail=no;;
     *) ac_prog_version="$ac_prog_version, bad"; ac_verc_fail=yes;;

diff -Nur glibc-2.12.2/math/bits/mathcalls.h glibc-2.12.2-patched/math/bits/mathcalls.h
--- glibc-2.12.2/math/bits/mathcalls.h  2010-12-13 02:47:26.000000000 -0800
+++ glibc-2.12.2-patched/math/bits/mathcalls.h  2016-07-17 14:51:30.329424398 -0700
@@ -197,9 +197,11 @@
 _Mdouble_END_NAMESPACE

 #ifdef __USE_MISC
+# if !defined __cplusplus || __cplusplus < 201103L /* Conflicts with C++11.  */
 /* Return 0 if VALUE is finite or NaN, +1 if it
    is +Infinity, -1 if it is -Infinity.  */
 __MATHDECL_1 (int,isinf,, (_Mdouble_ __value)) __attribute__ ((__const__));
+#endif

 /* Return nonzero if VALUE is finite and not NaN.  */
 __MATHDECL_1 (int,finite,, (_Mdouble_ __value)) __attribute__ ((__const__));
@@ -226,13 +228,14 @@
 __END_NAMESPACE_C99
 #endif

-
 /* Return nonzero if VALUE is not a number.  */
 __MATHDECL_1 (int,__isnan,, (_Mdouble_ __value)) __attribute__ ((__const__));

 #if defined __USE_MISC || defined __USE_XOPEN
+# if !defined __cplusplus || __cplusplus < 201103L /* Conflicts with C++11.  */
 /* Return nonzero if VALUE is not a number.  */
 __MATHDECL_1 (int,isnan,, (_Mdouble_ __value)) __attribute__ ((__const__));
+#endif

 /* Bessel functions.  */
 __MATHCALL (j0,, (_Mdouble_));
diff --git a/include/features.h b/include/features.h
index d9b6de9..05677a9 100644
--- a/include/features.h
+++ b/include/features.h
@@ -338,7 +338,7 @@
 /* Major and minor version number of the GNU C library package.  Use
    these macros to test for features in specific releases.  */
 #define	__GLIBC__	2
-#define	__GLIBC_MINOR__	13
+#define	__GLIBC_MINOR__	12
 
 #define __GLIBC_PREREQ(maj, min) \
	((__GLIBC__ << 16) + __GLIBC_MINOR__ >= ((maj) << 16) + (min))

diff --git a/malloc/obstack.c b/malloc/obstack.c
index 5786da0aa4..c27a422077 100644
--- a/malloc/obstack.c
+++ b/malloc/obstack.c
@@ -116,7 +116,7 @@ int obstack_exit_failure = EXIT_FAILURE;
 /* A looong time ago (before 1994, anyway; we're not sure) this global variable
    was used by non-GNU-C macros to avoid multiple evaluation.  The GNU C
    library still exports it because somebody might use it.  */
-struct obstack *_obstack_compat;
+struct obstack *_obstack_compat = 0;
 compat_symbol (libc, _obstack_compat, _obstack, GLIBC_2_0);
 #  endif
 # endif
