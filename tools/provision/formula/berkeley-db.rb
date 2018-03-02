require File.expand_path("../Abstract/abstract-osquery-formula", __FILE__)

class BerkeleyDb < AbstractOsqueryFormula
  desc "High performance key/value database"
  homepage "https://www.oracle.com/technology/products/berkeley-db/index.html"
  license "Sleepycat"
  url "http://pkgs.fedoraproject.org/repo/pkgs/libdb/db-5.3.28.tar.gz/b99454564d5b4479750567031d66fe24/db-5.3.28.tar.gz"
  sha256 "e0a992d740709892e81f9d93f06daf305cf73fb81b545afe72478043172c3628"
  revision 100

  bottle do
    root_url "https://osquery-packages.s3.amazonaws.com/bottles"
    cellar :any_skip_relocation
    sha256 "05e96e4323c562cc163a7374b988c26e2ca2f12984dd3557c77d9b7a6ee03f39" => :sierra
    sha256 "60b5a48a043c22f8eeb49cbdcddad3b0f4e737bbe9aea68eeb7474ac30f3465d" => :x86_64_linux
  end

  # Fix inline atomic compare exchange.
  patch :DATA

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

__END__
diff --git a/src/dbinc/atomic.h b/src/dbinc/atomic.h
index 6a858f7..c0a0ee7 100644
--- a/src/dbinc/atomic.h
+++ b/src/dbinc/atomic.h
@@ -144,7 +144,7 @@ typedef LONG volatile *interlocked_val;
 #define	atomic_inc(env, p)	__atomic_inc(p)
 #define	atomic_dec(env, p)	__atomic_dec(p)
 #define	atomic_compare_exchange(env, p, o, n)	\
-	__atomic_compare_exchange((p), (o), (n))
+	__atomic_compare_exchange_db((p), (o), (n))
 static inline int __atomic_inc(db_atomic_t *p)
 {
	int	temp;
@@ -176,7 +176,7 @@ static inline int __atomic_dec(db_atomic_t *p)
  * http://gcc.gnu.org/onlinedocs/gcc-4.1.0/gcc/Atomic-Builtins.html
  * which configure could be changed to use.
  */
-static inline int __atomic_compare_exchange(
+static inline int __atomic_compare_exchange_db(
	db_atomic_t *p, atomic_value_t oldval, atomic_value_t newval)
 {
	atomic_value_t was;
