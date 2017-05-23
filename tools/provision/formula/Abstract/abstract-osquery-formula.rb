require "formula"
require "extend/ENV/shared"

module SkipRelocation
  def skip_relocation?
    true
  end
end

def legacy_prefix
  Pathname.new(ENV["HOMEBREW_PREFIX"])/"legacy"
end

def default_prefix
  Pathname.new(ENV["HOMEBREW_PREFIX"])
end

def glib_prefix
  Pathname.new(Formula["osquery/osquery-local/glibc-legacy"].prefix)
end

class AbstractOsqueryFormula < Formula
  protected

  class << self
    def set_legacy
      Object.const_set(
        "HOMEBREW_PREFIX",
        legacy_prefix
      )
    end
  end

  def initialize(*)
    super

    # Inject a forced-skipped-relocation to support multiple runtimes.
    # At build/compile time the formula will choose the active runtime to link
    # against, this *should* remain during bottle generation and pouring.
    bottle_specification.extend(SkipRelocation)
  end

  def setup
    @setup = ENV.has_key?('ABSTRACT_OSQUERY_FORMULA')
    ENV['ABSTRACT_OSQUERY_FORMULA'] = '1'
    return @setup
  end

  def osquery_cmake_args
    includes = "#{default_prefix}/include"
    includes = "#{legacy_prefix}/include:#{includes}" if OS.linux?

    std_cmake_args + [
      "-DCMAKE_LIBRARY_PATH=#{ENV["LIBRARY_PATH"]}",
      "-DCMAKE_INCLUDE_PATH=#{includes}",
    ]
  end

  def reset(name)
    ENV.delete name
  end

  def append(name, value)
    ENV[name] = ENV.has_key?(name) ? ENV[name] + ' ' + value.to_s : value.to_s
  end

  def prepend(name, value)
    ENV[name] = ENV.has_key?(name) ? value.to_s + ' ' + ENV[name] : value.to_s
  end

  def prepend_path(name, value)
    ENV[name] = ENV.has_key?(name) ? value.to_s + ':' + ENV[name] : value.to_s
  end

  def self.method_added(name)
    return unless /install/.match(name.to_s)
    return if /inject/.match(name.to_s)
    return if /hook/.match(name.to_s) or method_defined?("#{name}_hook_target")

    hook = "def #{name}_hook\n setup_inject\n #{name}_hook_target\nend"
    self.class_eval(hook)
    target = "alias #{name}_hook_target #{name}"
    self.class_eval(target)
    inject_hook = "alias #{name} #{name}_hook"
    self.class_eval(inject_hook)
  end

  def setup_inject
    return if setup

    puts "Hello from osquery setup: #{name}"

    # Reset compile flags for safety, we want to control them explicitly.
    reset "CFLAGS"
    reset "CXXFLAGS"
    reset "CPPFLAGS"

    # Reset the following since the logic within the 'std' environment does not
    # known about our legacy runtime 'glibc' formula name.
    reset "LDFLAGS"
    reset "LD_LIBRARY_PATH"
    reset "LD_RUN_PATH"
    reset "CPATH"
    reset "LIBRARY_PATH"

    if !["glibc", "glibc-legacy"].include?(self.name)
      # The modern runtime is not brew-linked.

      prepend_path "LD_LIBRARY_PATH", lib
      prepend_path "LD_LIBRARY_PATH", prefix
      prepend_path "LIBRARY_PATH", default_prefix/"lib"

      # clang wants -L in the CFLAGS.
      # Several projects do not want this: pcre, RocksDB
      # These used to belong to !gcc but -lz wants the system libz.
      prepend "CFLAGS", "-L#{default_prefix}/lib"

      # This is already set to the PREFIX
      if !["gcc"].include?(self.name)
        # Set the dynamic linker and library search path.
        prepend "CFLAGS", "-isystem#{default_prefix}/include"

        # cmake wants this to have -I
        prepend "CXXFLAGS", "-I#{default_prefix}/include"

        prepend_path "LD_RUN_PATH", default_prefix/"lib"

        # Set the search path for header files.
        prepend_path "CPATH", default_prefix/"include"
      end

      # Adding this one line to help gcc too.
      if !["openssl"].include?(self.name)
        append "LDFLAGS", "-L#{default_prefix}/lib"
        # We want the legacy path to be the last thing prepended.
        prepend "LDFLAGS", "-L#{legacy_prefix}/lib" if OS.linux?
      end

      # Only Linux uses the Legacy prefix concept for glibc/zlib.
      prepend "CFLAGS", "-L#{legacy_prefix}/lib" if OS.linux?
      prepend "CXXFLAGS", "-I#{legacy_prefix}/include" if OS.linux?

      # This used to be in the GCC/not-GCC logic, pulling out to compile GCC
      # Using the system compilers with legacy runtime.
      prepend "CFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?
      prepend "CXXFLAGS", "-isystem#{legacy_prefix}/include" if OS.linux?

      prepend_path "LIBRARY_PATH", legacy_prefix/"lib" if OS.linux?

      append "LDFLAGS", "-Wl,-rpath,#{default_prefix}/lib"
      append "LDFLAGS", "-lrt -lpthread -ldl -lz" if OS.linux?
    end

    prepend_path "PATH", default_prefix/"bin" if OS.mac?
    prepend_path "PYTHONPATH", default_prefix/"lib/python2.7/site-packages" if OS.mac?

    # Everyone receives:
    append "CFLAGS", "-fPIC -DNDEBUG -Os -march=core2"
    append "CXXFLAGS", "-fPIC -DNDEBUG -Os -march=core2"

    if ENV["CC"].to_s.include?("clang") and !["librpm", "python"].include?(self.name)
      append "CFLAGS", "-fvisibility=hidden -fvisibility-inlines-hidden"
      append "CXXFLAGS", "-fvisibility=hidden -fvisibility-inlines-hidden"
      append "CFLAGS", "-Wno-unused-command-line-argument"
      append "CXXFLAGS", "-Wno-unused-command-line-argument"

      append "LDFLAGS", "-fuse-ld=lld" if OS.linux?
    end

    prepend_path "PKG_CONFIG_PATH", legacy_prefix/"lib/pkgconfig"

    self.audit
    reset "DEBUG"
  end

  def audit
    return if !ENV.has_key?("DEBUG")
    puts ":: PATH    : " + ENV["PATH"].to_s
    puts ":: CFLAGS  : " + ENV["CFLAGS"].to_s
    puts ":: CPPFLAGS: " + ENV["CPPFLAGS"].to_s
    puts ":: CXXFLAGS: " + ENV["CXXFLAGS"].to_s
    puts ":: LDFLAGS : " + ENV["LDFLAGS"].to_s
    puts ":: CC      : " + ENV["CC"].to_s
    puts ":: CXX     : " + ENV["CXX"].to_s
    puts ""
    puts ":: CPATH           : " + ENV["CPATH"].to_s
    puts ":: LD_LIBRARY_PATH : " + ENV["LD_LIBRARY_PATH"].to_s
    puts ":: LIBRARY_PATH    : " + ENV["LIBRARY_PATH"].to_s
    puts ":: LD_RUN_PATH     : " + ENV["LD_RUN_PATH"].to_s
    puts ":: PKG_CONFIG_PATH : " + ENV["PKG_CONFIG_PATH"].to_s
  end
end
