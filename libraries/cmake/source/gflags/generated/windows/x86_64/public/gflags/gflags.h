// Copyright (c) 2006, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// ---
// Revamped and reorganized by Craig Silverstein
//
// This is the file that should be included by any file which declares
// or defines a command line flag or wants to parse command line flags
// or print a program usage message (which will include information about
// flags).  Executive summary, in the form of an example foo.cc file:
//
//    #include "foo.h"         // foo.h has a line "DECLARE_int32(start);"
//    #include "validators.h"  // hypothetical file defining ValidateIsFile()
//
//    DEFINE_int32(end, 1000, "The last record to read");
//
//    DEFINE_string(filename, "my_file.txt", "The file to read");
//    // Crash if the specified file does not exist.
//    static bool dummy = RegisterFlagValidator(&FLAGS_filename,
//                                              &ValidateIsFile);
//
//    DECLARE_bool(verbose); // some other file has a DEFINE_bool(verbose, ...)
//
//    void MyFunc() {
//      if (FLAGS_verbose) printf("Records %d-%d\n", FLAGS_start, FLAGS_end);
//    }
//
//    Then, at the command-line:
//       ./foo --noverbose --start=5 --end=100
//
// For more details, see
//    doc/gflags.html
//
// --- A note about thread-safety:
//
// We describe many functions in this routine as being thread-hostile,
// thread-compatible, or thread-safe.  Here are the meanings we use:
//
// thread-safe: it is safe for multiple threads to call this routine
//   (or, when referring to a class, methods of this class)
//   concurrently.
// thread-hostile: it is not safe for multiple threads to call this
//   routine (or methods of this class) concurrently.  In gflags,
//   most thread-hostile routines are intended to be called early in,
//   or even before, main() -- that is, before threads are spawned.
// thread-compatible: it is safe for multiple threads to read from
//   this variable (when applied to variables), or to call const
//   methods of this class (when applied to classes), as long as no
//   other thread is writing to the variable or calling non-const
//   methods of this class.

#ifndef GFLAGS_GFLAGS_H_
#define GFLAGS_GFLAGS_H_

#include <string>
#include <vector>

#include "gflags/gflags_declare.h" // IWYU pragma: export


// We always want to export variables defined in user code
#ifndef GFLAGS_DLL_DEFINE_FLAG
#  if GFLAGS_IS_A_DLL && defined(_MSC_VER)
#    define GFLAGS_DLL_DEFINE_FLAG __declspec(dllexport)
#  else
#    define GFLAGS_DLL_DEFINE_FLAG
#  endif
#endif


namespace GFLAGS_NAMESPACE {


// --------------------------------------------------------------------
// To actually define a flag in a file, use DEFINE_bool,
// DEFINE_string, etc. at the bottom of this file.  You may also find
// it useful to register a validator with the flag.  This ensures that
// when the flag is parsed from the commandline, or is later set via
// SetCommandLineOption, we call the validation function. It is _not_
// called when you assign the value to the flag directly using the = operator.
//
// The validation function should return true if the flag value is valid, and
// false otherwise. If the function returns false for the new setting of the
// flag, the flag will retain its current value. If it returns false for the
// default value, ParseCommandLineFlags() will die.
//
// This function is safe to call at global construct time (as in the
// example below).
//
// Example use:
//    static bool ValidatePort(const char* flagname, int32 value) {
//       if (value > 0 && value < 32768)   // value is ok
//         return true;
//       printf("Invalid value for --%s: %d\n", flagname, (int)value);
//       return false;
//    }
//    DEFINE_int32(port, 0, "What port to listen on");
//    static bool dummy = RegisterFlagValidator(&FLAGS_port, &ValidatePort);

// Returns true if successfully registered, false if not (because the
// first argument doesn't point to a command-line flag, or because a
// validator is already registered for this flag).
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const bool*        flag, bool (*validate_fn)(const char*, bool));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const int32*       flag, bool (*validate_fn)(const char*, int32));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const uint32*      flag, bool (*validate_fn)(const char*, uint32));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const int64*       flag, bool (*validate_fn)(const char*, int64));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const uint64*      flag, bool (*validate_fn)(const char*, uint64));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const double*      flag, bool (*validate_fn)(const char*, double));
extern GFLAGS_DLL_DECL bool RegisterFlagValidator(const std::string* flag, bool (*validate_fn)(const char*, const std::string&));

// Convenience macro for the registration of a flag validator
#define DEFINE_validator(name, validator) \
    static const bool name##_validator_registered = \
            GFLAGS_NAMESPACE::RegisterFlagValidator(&FLAGS_##name, validator)


// --------------------------------------------------------------------
// These methods are the best way to get access to info about the
// list of commandline flags.  Note that these routines are pretty slow.
//   GetAllFlags: mostly-complete info about the list, sorted by file.
//   ShowUsageWithFlags: pretty-prints the list to stdout (what --help does)
//   ShowUsageWithFlagsRestrict: limit to filenames with restrict as a substr
//
// In addition to accessing flags, you can also access argv[0] (the program
// name) and argv (the entire commandline), which we sock away a copy of.
// These variables are static, so you should only set them once.
//
// No need to export this data only structure from DLL, avoiding VS warning 4251.
struct CommandLineFlagInfo {
  std::string name;            // the name of the flag
  std::string type;            // the type of the flag: int32, etc
  std::string description;     // the "help text" associated with the flag
  std::string current_value;   // the current value, as a string
  std::string default_value;   // the default value, as a string
  std::string filename;        // 'cleaned' version of filename holding the flag
  bool has_validator_fn;       // true if RegisterFlagValidator called on this flag
  bool is_default;             // true if the flag has the default value and
                               // has not been set explicitly from the cmdline
                               // or via SetCommandLineOption
  const void* flag_ptr;        // pointer to the flag's current value (i.e. FLAGS_foo)
};

// Using this inside of a validator is a recipe for a deadlock.
// TODO(user) Fix locking when validators are running, to make it safe to
// call validators during ParseAllFlags.
// Also make sure then to uncomment the corresponding unit test in
// gflags_unittest.sh
extern GFLAGS_DLL_DECL void GetAllFlags(std::vector<CommandLineFlagInfo>* OUTPUT);
// These two are actually defined in gflags_reporting.cc.
extern GFLAGS_DLL_DECL void ShowUsageWithFlags(const char *argv0);  // what --help does
extern GFLAGS_DLL_DECL void ShowUsageWithFlagsRestrict(const char *argv0, const char *restrict);

// Create a descriptive string for a flag.
// Goes to some trouble to make pretty line breaks.
extern GFLAGS_DLL_DECL std::string DescribeOneFlag(const CommandLineFlagInfo& flag);

// Thread-hostile; meant to be called before any threads are spawned.
extern GFLAGS_DLL_DECL void SetArgv(int argc, const char** argv);

// The following functions are thread-safe as long as SetArgv() is
// only called before any threads start.
extern GFLAGS_DLL_DECL const std::vector<std::string>& GetArgvs();
extern GFLAGS_DLL_DECL const char* GetArgv();                      // all of argv as a string
extern GFLAGS_DLL_DECL const char* GetArgv0();                     // only argv0
extern GFLAGS_DLL_DECL uint32 GetArgvSum();                        // simple checksum of argv
extern GFLAGS_DLL_DECL const char* ProgramInvocationName();        // argv0, or "UNKNOWN" if not set
extern GFLAGS_DLL_DECL const char* ProgramInvocationShortName();   // basename(argv0)

// ProgramUsage() is thread-safe as long as SetUsageMessage() is only
// called before any threads start.
extern GFLAGS_DLL_DECL const char* ProgramUsage();                 // string set by SetUsageMessage()

// VersionString() is thread-safe as long as SetVersionString() is only
// called before any threads start.
extern GFLAGS_DLL_DECL const char* VersionString();                // string set by SetVersionString()



// --------------------------------------------------------------------
// Normally you access commandline flags by just saying "if (FLAGS_foo)"
// or whatever, and set them by calling "FLAGS_foo = bar" (or, more
// commonly, via the DEFINE_foo macro).  But if you need a bit more
// control, we have programmatic ways to get/set the flags as well.
// These programmatic ways to access flags are thread-safe, but direct
// access is only thread-compatible.

// Return true iff the flagname was found.
// OUTPUT is set to the flag's value, or unchanged if we return false.
extern GFLAGS_DLL_DECL bool GetCommandLineOption(const char* name, std::string* OUTPUT);

// Return true iff the flagname was found. OUTPUT is set to the flag's
// CommandLineFlagInfo or unchanged if we return false.
extern GFLAGS_DLL_DECL bool GetCommandLineFlagInfo(const char* name, CommandLineFlagInfo* OUTPUT);

// Return the CommandLineFlagInfo of the flagname.  exit() if name not found.
// Example usage, to check if a flag's value is currently the default value:
//   if (GetCommandLineFlagInfoOrDie("foo").is_default) ...
extern GFLAGS_DLL_DECL CommandLineFlagInfo GetCommandLineFlagInfoOrDie(const char* name);

enum GFLAGS_DLL_DECL FlagSettingMode {
  // update the flag's value (can call this multiple times).
  SET_FLAGS_VALUE,
  // update the flag's value, but *only if* it has not yet been updated
  // with SET_FLAGS_VALUE, SET_FLAG_IF_DEFAULT, or "FLAGS_xxx = nondef".
  SET_FLAG_IF_DEFAULT,
  // set the flag's default value to this.  If the flag has not yet updated
  // yet (via SET_FLAGS_VALUE, SET_FLAG_IF_DEFAULT, or "FLAGS_xxx = nondef")
  // change the flag's current value to the new default value as well.
  SET_FLAGS_DEFAULT
};

// Set a particular flag ("command line option").  Returns a string
// describing the new value that the option has been set to.  The
// return value API is not well-specified, so basically just depend on
// it to be empty if the setting failed for some reason -- the name is
// not a valid flag name, or the value is not a valid value -- and
// non-empty else.

// SetCommandLineOption uses set_mode == SET_FLAGS_VALUE (the common case)
extern GFLAGS_DLL_DECL std::string SetCommandLineOption        (const char* name, const char* value);
extern GFLAGS_DLL_DECL std::string SetCommandLineOptionWithMode(const char* name, const char* value, FlagSettingMode set_mode);


// --------------------------------------------------------------------
// Saves the states (value, default value, whether the user has set
// the flag, registered validators, etc) of all flags, and restores
// them when the FlagSaver is destroyed.  This is very useful in
// tests, say, when you want to let your tests change the flags, but
// make sure that they get reverted to the original states when your
// test is complete.
//
// Example usage:
//   void TestFoo() {
//     FlagSaver s1;
//     FLAG_foo = false;
//     FLAG_bar = "some value";
//
//     // test happens here.  You can return at any time
//     // without worrying about restoring the FLAG values.
//   }
//
// Note: This class is marked with GFLAGS_ATTRIBUTE_UNUSED because all
// the work is done in the constructor and destructor, so in the standard
// usage example above, the compiler would complain that it's an
// unused variable.
//
// This class is thread-safe.  However, its destructor writes to
// exactly the set of flags that have changed value during its
// lifetime, so concurrent _direct_ access to those flags
// (i.e. FLAGS_foo instead of {Get,Set}CommandLineOption()) is unsafe.

class GFLAGS_DLL_DECL FlagSaver {
 public:
  FlagSaver();
  ~FlagSaver();

 private:
  class FlagSaverImpl* impl_;   // we use pimpl here to keep API steady

  FlagSaver(const FlagSaver&);  // no copying!
  void operator=(const FlagSaver&);
};

// --------------------------------------------------------------------
// Some deprecated or hopefully-soon-to-be-deprecated functions.

// This is often used for logging.  TODO(csilvers): figure out a better way
extern GFLAGS_DLL_DECL std::string CommandlineFlagsIntoString();
// Usually where this is used, a FlagSaver should be used instead.
extern GFLAGS_DLL_DECL
bool ReadFlagsFromString(const std::string& flagfilecontents,
                         const char* prog_name,
                         bool errors_are_fatal);  // uses SET_FLAGS_VALUE

// These let you manually implement --flagfile functionality.
// DEPRECATED.
extern GFLAGS_DLL_DECL bool AppendFlagsIntoFile(const std::string& filename, const char* prog_name);
extern GFLAGS_DLL_DECL bool ReadFromFlagsFile(const std::string& filename, const char* prog_name, bool errors_are_fatal);   // uses SET_FLAGS_VALUE


// --------------------------------------------------------------------
// Useful routines for initializing flags from the environment.
// In each case, if 'varname' does not exist in the environment
// return defval.  If 'varname' does exist but is not valid
// (e.g., not a number for an int32 flag), abort with an error.
// Otherwise, return the value.  NOTE: for booleans, for true use
// 't' or 'T' or 'true' or '1', for false 'f' or 'F' or 'false' or '0'.

extern GFLAGS_DLL_DECL bool BoolFromEnv(const char *varname, bool defval);
extern GFLAGS_DLL_DECL int32 Int32FromEnv(const char *varname, int32 defval);
extern GFLAGS_DLL_DECL uint32 Uint32FromEnv(const char *varname, uint32 defval);
extern GFLAGS_DLL_DECL int64 Int64FromEnv(const char *varname, int64 defval);
extern GFLAGS_DLL_DECL uint64 Uint64FromEnv(const char *varname, uint64 defval);
extern GFLAGS_DLL_DECL double DoubleFromEnv(const char *varname, double defval);
extern GFLAGS_DLL_DECL const char *StringFromEnv(const char *varname, const char *defval);


// --------------------------------------------------------------------
// The next two functions parse gflags from main():

// Set the "usage" message for this program.  For example:
//   string usage("This program does nothing.  Sample usage:\n");
//   usage += argv[0] + " <uselessarg1> <uselessarg2>";
//   SetUsageMessage(usage);
// Do not include commandline flags in the usage: we do that for you!
// Thread-hostile; meant to be called before any threads are spawned.
extern GFLAGS_DLL_DECL void SetUsageMessage(const std::string& usage);

// Sets the version string, which is emitted with --version.
// For instance: SetVersionString("1.3");
// Thread-hostile; meant to be called before any threads are spawned.
extern GFLAGS_DLL_DECL void SetVersionString(const std::string& version);


// Looks for flags in argv and parses them.  Rearranges argv to put
// flags first, or removes them entirely if remove_flags is true.
// If a flag is defined more than once in the command line or flag
// file, the last definition is used.  Returns the index (into argv)
// of the first non-flag argument.
// See top-of-file for more details on this function.
#ifndef SWIG   // In swig, use ParseCommandLineFlagsScript() instead.
extern GFLAGS_DLL_DECL uint32 ParseCommandLineFlags(int *argc, char*** argv, bool remove_flags);
#endif


// Calls to ParseCommandLineNonHelpFlags and then to
// HandleCommandLineHelpFlags can be used instead of a call to
// ParseCommandLineFlags during initialization, in order to allow for
// changing default values for some FLAGS (via
// e.g. SetCommandLineOptionWithMode calls) between the time of
// command line parsing and the time of dumping help information for
// the flags as a result of command line parsing.  If a flag is
// defined more than once in the command line or flag file, the last
// definition is used.  Returns the index (into argv) of the first
// non-flag argument.  (If remove_flags is true, will always return 1.)
extern GFLAGS_DLL_DECL uint32 ParseCommandLineNonHelpFlags(int *argc, char*** argv, bool remove_flags);

// This is actually defined in gflags_reporting.cc.
// This function is misnamed (it also handles --version, etc.), but
// it's too late to change that now. :-(
extern GFLAGS_DLL_DECL void HandleCommandLineHelpFlags();   // in gflags_reporting.cc

// Allow command line reparsing.  Disables the error normally
// generated when an unknown flag is found, since it may be found in a
// later parse.  Thread-hostile; meant to be called before any threads
// are spawned.
extern GFLAGS_DLL_DECL void AllowCommandLineReparsing();

// Reparse the flags that have not yet been recognized.  Only flags
// registered since the last parse will be recognized.  Any flag value
// must be provided as part of the argument using "=", not as a
// separate command line argument that follows the flag argument.
// Intended for handling flags from dynamically loaded libraries,
// since their flags are not registered until they are loaded.
extern GFLAGS_DLL_DECL void ReparseCommandLineNonHelpFlags();

// Clean up memory allocated by flags.  This is only needed to reduce
// the quantity of "potentially leaked" reports emitted by memory
// debugging tools such as valgrind.  It is not required for normal
// operation, or for the google perftools heap-checker.  It must only
// be called when the process is about to exit, and all threads that
// might access flags are quiescent.  Referencing flags after this is
// called will have unexpected consequences.  This is not safe to run
// when multiple threads might be running: the function is
// thread-hostile.
extern GFLAGS_DLL_DECL void ShutDownCommandLineFlags();


// --------------------------------------------------------------------
// Now come the command line flag declaration/definition macros that
// will actually be used.  They're kind of hairy.  A major reason
// for this is initialization: we want people to be able to access
// variables in global constructors and have that not crash, even if
// their global constructor runs before the global constructor here.
// (Obviously, we can't guarantee the flags will have the correct
// default value in that case, but at least accessing them is safe.)
// The only way to do that is have flags point to a static buffer.
// So we make one, using a union to ensure proper alignment, and
// then use placement-new to actually set up the flag with the
// correct default value.  In the same vein, we have to worry about
// flag access in global destructors, so FlagRegisterer has to be
// careful never to destroy the flag-values it constructs.
//
// Note that when we define a flag variable FLAGS_<name>, we also
// preemptively define a junk variable, FLAGS_no<name>.  This is to
// cause a link-time error if someone tries to define 2 flags with
// names like "logging" and "nologging".  We do this because a bool
// flag FLAG can be set from the command line to true with a "-FLAG"
// argument, and to false with a "-noFLAG" argument, and so this can
// potentially avert confusion.
//
// We also put flags into their own namespace.  It is purposefully
// named in an opaque way that people should have trouble typing
// directly.  The idea is that DEFINE puts the flag in the weird
// namespace, and DECLARE imports the flag from there into the current
// namespace.  The net result is to force people to use DECLARE to get
// access to a flag, rather than saying "extern GFLAGS_DLL_DECL bool FLAGS_whatever;"
// or some such instead.  We want this so we can put extra
// functionality (like sanity-checking) in DECLARE if we want, and
// make sure it is picked up everywhere.
//
// We also put the type of the variable in the namespace, so that
// people can't DECLARE_int32 something that they DEFINE_bool'd
// elsewhere.

class GFLAGS_DLL_DECL FlagRegisterer {
 public:
  // We instantiate this template ctor for all supported types,
  // so it is possible to place implementation of the FlagRegisterer ctor in
  // .cc file.
  // Calling this constructor with unsupported type will produce linker error.
  template <typename FlagType>
  FlagRegisterer(const char* name,
                 const char* help, const char* filename,
                 FlagType* current_storage, FlagType* defvalue_storage);
};

// Force compiler to not generate code for the given template specialization.
#if defined(_MSC_VER) && _MSC_VER < 1800 // Visual Studio 2013 version 12.0
  #define GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(type)
#else
  #define GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(type)                  \
    extern template GFLAGS_DLL_DECL FlagRegisterer::FlagRegisterer(  \
        const char* name, const char* help, const char* filename,    \
        type* current_storage, type* defvalue_storage)
#endif

// Do this for all supported flag types.
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(bool);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(int32);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(uint32);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(int64);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(uint64);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(double);
GFLAGS_DECLARE_FLAG_REGISTERER_CTOR(std::string);

#undef GFLAGS_DECLARE_FLAG_REGISTERER_CTOR

// If your application #defines STRIP_FLAG_HELP to a non-zero value
// before #including this file, we remove the help message from the
// binary file. This can reduce the size of the resulting binary
// somewhat, and may also be useful for security reasons.

extern GFLAGS_DLL_DECL const char kStrippedFlagHelp[];


} // namespace GFLAGS_NAMESPACE


#ifndef SWIG  // In swig, ignore the main flag declarations

#if defined(STRIP_FLAG_HELP) && STRIP_FLAG_HELP > 0
// Need this construct to avoid the 'defined but not used' warning.
#define MAYBE_STRIPPED_HELP(txt) \
   (false ? (txt) : GFLAGS_NAMESPACE::kStrippedFlagHelp)
#else
#define MAYBE_STRIPPED_HELP(txt) txt
#endif

// Each command-line flag has two variables associated with it: one
// with the current value, and one with the default value.  However,
// we have a third variable, which is where value is assigned; it's a
// constant.  This guarantees that FLAG_##value is initialized at
// static initialization time (e.g. before program-start) rather than
// than global construction time (which is after program-start but
// before main), at least when 'value' is a compile-time constant.  We
// use a small trick for the "default value" variable, and call it
// FLAGS_no<name>.  This serves the second purpose of assuring a
// compile error if someone tries to define a flag named no<name>
// which is illegal (--foo and --nofoo both affect the "foo" flag).
#define DEFINE_VARIABLE(type, shorttype, name, value, help)             \
  namespace fL##shorttype {                                             \
    static const type FLAGS_nono##name = value;                         \
    /* We always want to export defined variables, dll or no */         \
    GFLAGS_DLL_DEFINE_FLAG type FLAGS_##name = FLAGS_nono##name;        \
    static type FLAGS_no##name = FLAGS_nono##name;                      \
    static GFLAGS_NAMESPACE::FlagRegisterer o_##name(                   \
      #name, MAYBE_STRIPPED_HELP(help), __FILE__,                       \
      &FLAGS_##name, &FLAGS_no##name);                                  \
  }                                                                     \
  using fL##shorttype::FLAGS_##name

// For DEFINE_bool, we want to do the extra check that the passed-in
// value is actually a bool, and not a string or something that can be
// coerced to a bool.  These declarations (no definition needed!) will
// help us do that, and never evaluate From, which is important.
// We'll use 'sizeof(IsBool(val))' to distinguish. This code requires
// that the compiler have different sizes for bool & double. Since
// this is not guaranteed by the standard, we check it with a
// COMPILE_ASSERT.
namespace fLB {
struct CompileAssert {};
typedef CompileAssert expected_sizeof_double_neq_sizeof_bool[
                      (sizeof(double) != sizeof(bool)) ? 1 : -1];
template<typename From> double GFLAGS_DLL_DECL IsBoolFlag(const From& from);
GFLAGS_DLL_DECL bool IsBoolFlag(bool from);
}  // namespace fLB

// Here are the actual DEFINE_*-macros. The respective DECLARE_*-macros
// are in a separate include, gflags_declare.h, for reducing
// the physical transitive size for DECLARE use.
#define DEFINE_bool(name, val, txt)                                     \
  namespace fLB {                                                       \
    typedef ::fLB::CompileAssert FLAG_##name##_value_is_not_a_bool[     \
            (sizeof(::fLB::IsBoolFlag(val)) != sizeof(double))? 1: -1]; \
  }                                                                     \
  DEFINE_VARIABLE(bool, B, name, val, txt)

#define DEFINE_int32(name, val, txt) \
   DEFINE_VARIABLE(GFLAGS_NAMESPACE::int32, I, \
                   name, val, txt)

#define DEFINE_uint32(name,val, txt) \
   DEFINE_VARIABLE(GFLAGS_NAMESPACE::uint32, U, \
                   name, val, txt)

#define DEFINE_int64(name, val, txt) \
   DEFINE_VARIABLE(GFLAGS_NAMESPACE::int64, I64, \
                   name, val, txt)

#define DEFINE_uint64(name,val, txt) \
   DEFINE_VARIABLE(GFLAGS_NAMESPACE::uint64, U64, \
                   name, val, txt)

#define DEFINE_double(name, val, txt) \
   DEFINE_VARIABLE(double, D, name, val, txt)

// Strings are trickier, because they're not a POD, so we can't
// construct them at static-initialization time (instead they get
// constructed at global-constructor time, which is much later).  To
// try to avoid crashes in that case, we use a char buffer to store
// the string, which we can static-initialize, and then placement-new
// into it later.  It's not perfect, but the best we can do.

namespace fLS {

inline clstring* dont_pass0toDEFINE_string(char *stringspot,
                                           const char *value) {
  return new(stringspot) clstring(value);
}
inline clstring* dont_pass0toDEFINE_string(char *stringspot,
                                           const clstring &value) {
  return new(stringspot) clstring(value);
}
inline clstring* dont_pass0toDEFINE_string(char *stringspot,
                                           int value);

// Auxiliary class used to explicitly call destructor of string objects
// allocated using placement new during static program deinitialization.
// The destructor MUST be an inline function such that the explicit
// destruction occurs in the same compilation unit as the placement new.
class StringFlagDestructor {
  void *current_storage_;
  void *defvalue_storage_;

public: 

  StringFlagDestructor(void *current, void *defvalue)
  : current_storage_(current), defvalue_storage_(defvalue) {}

  ~StringFlagDestructor() {
    reinterpret_cast<clstring*>(current_storage_ )->~clstring();
    reinterpret_cast<clstring*>(defvalue_storage_)->~clstring();
  }
};

}  // namespace fLS

// We need to define a var named FLAGS_no##name so people don't define
// --string and --nostring.  And we need a temporary place to put val
// so we don't have to evaluate it twice.  Two great needs that go
// great together!
// The weird 'using' + 'extern' inside the fLS namespace is to work around
// an unknown compiler bug/issue with the gcc 4.2.1 on SUSE 10.  See
//    http://code.google.com/p/google-gflags/issues/detail?id=20
#define DEFINE_string(name, val, txt)                                       \
  namespace fLS {                                                           \
    using ::fLS::clstring;                                                  \
    using ::fLS::StringFlagDestructor;                                      \
    static union { void* align; char s[sizeof(clstring)]; } s_##name[2];    \
    clstring* const FLAGS_no##name = ::fLS::                                \
                                   dont_pass0toDEFINE_string(s_##name[0].s, \
                                                             val);          \
    static GFLAGS_NAMESPACE::FlagRegisterer o_##name(                       \
        #name, MAYBE_STRIPPED_HELP(txt), __FILE__,                          \
        FLAGS_no##name, new (s_##name[1].s) clstring(*FLAGS_no##name));     \
    static StringFlagDestructor d_##name(s_##name[0].s, s_##name[1].s);     \
    extern GFLAGS_DLL_DEFINE_FLAG clstring& FLAGS_##name;                   \
    using fLS::FLAGS_##name;                                                \
    clstring& FLAGS_##name = *FLAGS_no##name;                               \
  }                                                                         \
  using fLS::FLAGS_##name

#endif  // SWIG





#endif  // GFLAGS_GFLAGS_H_
