/*
** 2001 September 15
**
** The author disclaims copyright to this source code.  In place of
** a legal notice, here is a blessing:
**
**    May you do good and not evil.
**    May you find forgiveness for yourself and forgive others.
**    May you share freely, never taking more than you give.
**
*************************************************************************
** This file contains code to implement the "sqlite" command line
** utility for accessing SQLite databases.
*/

#include <csignal>
#include <cstdio>
#include <sstream>

#ifdef WIN32

#include <osquery/utils/system/system.h>

#include <io.h>
#else
#include <sys/resource.h>
#include <sys/time.h>
#endif

#include <linenoise.h>
#include <sqlite3.h>

#include <boost/algorithm/string/predicate.hpp>

#include <osquery/config/config.h>
#include <osquery/config/packs.h>
#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/devtools/devtools.h>
#include <osquery/extensions/interface.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/process/process.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/virtual_table.h>
#include <osquery/utils/chars.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/version.h>

#if defined(SQLITE_ENABLE_WHERETRACE)
extern int sqlite3WhereTrace;
#endif

namespace fs = boost::filesystem;

DECLARE_string(flagfile);

namespace osquery {

/// Define flags used by the shell. They are parsed by the drop-in shell.
SHELL_FLAG(bool, csv, false, "Set output mode to 'csv'");
SHELL_FLAG(bool, json, false, "Set output mode to 'json'");
SHELL_FLAG(bool, json_pretty, false, "Set output mode to 'json_pretty'");
SHELL_FLAG(bool, line, false, "Set output mode to 'line'");
SHELL_FLAG(bool, list, false, "Set output mode to 'list'");
SHELL_FLAG(string, separator, "|", "Set output field separator, default '|'");
SHELL_FLAG(bool, header, true, "Toggle column headers true/false");
SHELL_FLAG(string, pack, "", "Run all queries in a pack");

/// Define short-hand shell switches.
SHELL_FLAG(bool, L, false, "List all table names");
SHELL_FLAG(string, A, "", "Select all from a table");
SHELL_FLAG(string, connect, "", "Connect to an extension socket");

DECLARE_string(nullvalue);
DECLARE_string(extensions_socket);
DECLARE_string(tls_hostname);
DECLARE_string(logger_plugin);
DECLARE_string(logger_path);
DECLARE_string(logger_tls_endpoint);
DECLARE_string(distributed_plugin);
DECLARE_string(config_plugin);
DECLARE_string(config_path);
DECLARE_string(config_tls_endpoint);
DECLARE_string(database_path);
} // namespace osquery

static char zHelp[] =
    "Welcome to the osquery shell. Please explore your OS!\n"
    "You are connected to a transient 'in-memory' virtual database.\n"
    "\n"
    ".all [TABLE]     Select all from a table\n"
    ".bail ON|OFF     Stop after hitting an error\n"
    ".connect PATH    Connect to an osquery extension socket\n"
    ".disconnect      Disconnect from a connected extension socket\n"
    ".echo ON|OFF     Turn command echo on or off\n"
    ".exit            Exit this program\n"
    ".features        List osquery's features and their statuses\n"
    ".headers ON|OFF  Turn display of headers on or off\n"
    ".help            Show this message\n"
    ".mode MODE       Set output mode where MODE is one of:\n"
    "                   csv      Comma-separated values\n"
    "                   column   Left-aligned columns see .width\n"
    "                   line     One value per line\n"
    "                   list     Values delimited by .separator string\n"
    "                   pretty   Pretty printed SQL results (default)\n"
    ".nullvalue STR   Use STRING in place of NULL values\n"
    ".print STR...    Print literal STRING\n"
    ".quit            Exit this program\n"
    ".schema [TABLE]  Show the CREATE statements\n"
    ".separator STR   Change separator used by output mode\n"
    ".socket          Show the local osquery extensions socket path\n"
    ".show            Show the current values for various settings\n"
    ".summary         Alias for the show meta command\n"
    ".tables [TABLE]  List names of tables\n"
    ".types [SQL]     Show result of getQueryColumns for the given query\n"
    ".width [NUM1]+   Set column widths for \"column\" mode\n";

static char zTimerHelp[] =
    ".timer ON|OFF      Turn the CPU timer measurement on or off\n";

// Allowed modes
#define MODE_Line 0 // One column per line.  Blank line between records
#define MODE_Column 1 // One record per line in neat columns
#define MODE_List 2 // One record per line with a separator
#define MODE_Semi 3 // Same as MODE_List but append ";" to each line
#define MODE_Csv 4 // Quote strings, numbers are plain
#define MODE_Pretty 5 // Pretty print the SQL results

static const char* modeDescr[] = {
    "line",
    "column",
    "list",
    "semi",
    "csv",
    "pretty",
};

// ctype macros that work with signed characters
#define IsSpace(X) isspace((unsigned char)(X))
#define IsDigit(X) isdigit((unsigned char)(X))

// True if the timer is enabled
static int enableTimer = 0;

// Return the current wall-clock time
static sqlite3_int64 timeOfDay() {
  static sqlite3_vfs* clockVfs = nullptr;
  sqlite3_int64 t;
  if (clockVfs == nullptr) {
    clockVfs = sqlite3_vfs_find(nullptr);
  }
  if (clockVfs->iVersion >= 1 && clockVfs->xCurrentTimeInt64 != nullptr) {
    clockVfs->xCurrentTimeInt64(clockVfs, &t);
  } else {
    double r;
    clockVfs->xCurrentTime(clockVfs, &r);
    t = static_cast<sqlite3_int64>(r * 86400000.0);
  }
  return t;
}

// Saved resource information for the beginning of an operation
#ifdef WIN32
struct rusage {
  FILETIME ru_utime;
  FILETIME ru_stime;
};
#endif

static struct rusage sBegin; // CPU time at start
static sqlite3_int64 iBegin; // Wall-clock time at start

static void beginTimer() {
  if (enableTimer != 0) {
#ifdef WIN32
    FILETIME ftCreation, ftExit;
    ::GetProcessTimes(::GetCurrentProcess(),
                      &ftCreation,
                      &ftExit,
                      &sBegin.ru_stime,
                      &sBegin.ru_utime);
#else
    getrusage(RUSAGE_SELF, &sBegin);
#endif

    iBegin = timeOfDay();
  }
}

// Return the difference of two time_structs in seconds
#ifdef WIN32
static double timeDiff(FILETIME* pStart, FILETIME* pEnd) {
  ULARGE_INTEGER start, end;

  start.HighPart = pStart->dwHighDateTime;
  start.LowPart = pStart->dwLowDateTime;

  end.HighPart = pEnd->dwHighDateTime;
  end.LowPart = pEnd->dwLowDateTime;

  // start, end are in units of 100 nanoseconds
  return (end.QuadPart - start.QuadPart) * 0.0000001;
}
#else
static double timeDiff(struct timeval* pStart, struct timeval* pEnd) {
  return (pEnd->tv_usec - pStart->tv_usec) * 0.000001 +
         static_cast<double>(pEnd->tv_sec - pStart->tv_sec);
}
#endif

// End the timer and print the results.
static void endTimer() {
  if (enableTimer != 0) {
    sqlite3_int64 iEnd = timeOfDay();
    struct rusage sEnd {};

#ifdef WIN32
    FILETIME ftCreation, ftExit;
    ::GetProcessTimes(::GetCurrentProcess(),
                      &ftCreation,
                      &ftExit,
                      &sEnd.ru_stime,
                      &sEnd.ru_utime);
#else
    getrusage(RUSAGE_SELF, &sEnd);
#endif

    printf("Run Time: real %.3f user %f sys %f\n",
           (iEnd - iBegin) * 0.001,
           timeDiff(&sBegin.ru_utime, &sEnd.ru_utime),
           timeDiff(&sBegin.ru_stime, &sEnd.ru_stime));
  }
}

#define BEGIN_TIMER beginTimer()
#define END_TIMER endTimer()
#define HAS_TIMER 1

// If the following flag is set, then command execution stops
// at an error if we are not interactive.
static int bail_on_error = 0;

// Treat stdin as an interactive input if the following variable
// is true.  Otherwise, assume stdin is connected to a file or pipe.
static bool stdin_is_interactive = true;

// True if an interrupt (Control-C) has been received.
static volatile int seenInterrupt = 0;

static char mainPrompt[30]; // First line prompt. default: "sqlite> "
static char continuePrompt[30]; // Continuation prompt. default: "   ...> "

// A global char* and an SQL function to access its current value
// from within an SQL statement. This program used to use the
// sqlite_exec_printf() API to substitute a string into an SQL statement.
// The correct way to do this with sqlite3 is to use the bind API, but
// since the shell is built around the callback paradigm it would be a lot
// of work. Instead just use this hack, which is quite harmless.
static const char* zShellStatic = nullptr;
void shellstaticFunc(sqlite3_context* context,
                     int argc,
                     sqlite3_value** /* argv */) {
  (void)argc;
  assert(0 == argc);
  assert(zShellStatic);
  sqlite3_result_text(context, zShellStatic, -1, SQLITE_STATIC);
}

/*
** Output text to the console in a font that attracts extra attention.
*/
static void print_bold(const char* zText) {
  if (stdin_is_interactive) {
    printf("\033[1m");
  }
  printf("%s", zText);
  if (stdin_is_interactive) {
    printf("\033[0m");
  }
}

static void connect_socket() {
  print_bold("Connected to extension socket ");
  print_bold(osquery::FLAGS_connect.c_str());
  print_bold(" for debugging\n");

  std::string backup_prompt(mainPrompt);
  sqlite3_snprintf(
      sizeof(mainPrompt), mainPrompt, "[*]%s", backup_prompt.c_str());
  backup_prompt = continuePrompt;
  sqlite3_snprintf(
      sizeof(continuePrompt), continuePrompt, "[*]%s", backup_prompt.c_str());
}

static void disconnect_socket() {
  print_bold("Disconnected from extension socket ");
  print_bold(osquery::FLAGS_connect.c_str());
  print_bold("\n");

  std::string backup_prompt(mainPrompt + strlen("[*]"));
  sqlite3_snprintf(sizeof(mainPrompt), mainPrompt, backup_prompt.c_str());
  backup_prompt = continuePrompt + strlen("[*]");
  sqlite3_snprintf(
      sizeof(continuePrompt), continuePrompt, backup_prompt.c_str());
}

/*
** This routine reads a line of text from FILE in, stores
** the text in memory obtained from malloc() and returns a pointer
** to the text.  NULL is returned at end of file, or if malloc()
** fails.
**
** If zLine is not NULL then it is a malloced buffer returned from
** a previous call to this routine that may be reused.
*/
static char* local_getline(char* zLine, FILE* in) {
  int nLine = ((zLine == nullptr) ? 0 : 100);
  int n = 0;

  while (true) {
    if (n + 100 > nLine) {
      nLine = nLine * 2 + 100;
      auto zLine_new = reinterpret_cast<char*>(realloc(zLine, nLine));
      if (zLine_new == nullptr) {
        free(zLine);
        return nullptr;
      }
      zLine = zLine_new;
    }
    if (fgets(&zLine[n], nLine - n, in) == nullptr) {
      if (n == 0) {
        free(zLine);
        return nullptr;
      }
      zLine[n] = 0;
      break;
    }
    while (zLine[n] != 0) {
      n++;
    }
    if (n > 0 && zLine[n - 1] == '\n') {
      n--;
      if (n > 0 && zLine[n - 1] == '\r') {
        n--;
      }
      zLine[n] = 0;
      break;
    }
  }
  return zLine;
}

/*
** Retrieve a single line of input text.
**
** If in==0 then read from standard input and prompt before each line.
** If isContinuation is true, then a continuation prompt is appropriate.
** If isContinuation is zero, then the main prompt should be used.
**
** If zPrior is not NULL then it is a buffer from a prior call to this
** routine that can be reused.
**
** The result is stored in space obtained from malloc() and must either
** be freed by the caller or else passed back into this routine via the
** zPrior argument for reuse.
*/
static char* one_input_line(FILE* in, char* zPrior, int isContinuation) {
  char* zResult;
  if (in != nullptr) {
    zResult = local_getline(zPrior, in);
  } else {
    char* zPrompt = isContinuation != 0 ? continuePrompt : mainPrompt;
    free(zPrior);
    zResult = linenoise(zPrompt);
    if ((zResult != nullptr) && (*zResult != 0)) {
      linenoiseHistoryAdd(zResult);
    }
  }
  return zResult;
}

/*
** Pretty print structure
*/
struct prettyprint_data {
  osquery::QueryData results;
  std::vector<std::string> columns;
  std::map<std::string, size_t> lengths;
};

/*
** An pointer to an instance of this structure is passed from
** the main program to the callback.  This is used to communicate
** state and mode information.
*/
struct callback_data {
  int echoOn; /* True to echo input commands */
  int cnt; /* Number of records displayed so far */
  FILE* out; /* Write results here */
  FILE* traceOut; /* Output for sqlite3_trace() */
  int mode; /* An output mode setting */
  int showHeader; /* True to show column names in List or Column mode */
  char* zDestTable; /* Name of destination table when MODE_Insert */
  char separator[20]; /* Separator character for MODE_List */
  int colWidth[100]; /* Requested width of each column when in column mode*/
  int actualWidth[100]; /* Actual width of each column */
  char nullvalue[20]; /* The text to print when a NULL comes back from
                      ** the database */
  char outfile[FILENAME_MAX]; /* Filename for *out */
  sqlite3_stmt* pStmt; /* Current statement if any. */
  FILE* pLog; /* Write log output here */
  int* aiIndent; /* Array of indents used in MODE_Explain */
  int nIndent; /* Size of array aiIndent[] */
  int iIndent; /* Index of current op in aiIndent[] */

  /* Additional attributes to be used in pretty mode */
  struct prettyprint_data* prettyPrint;
};

// Number of elements in an array
#define ArraySize(X) (int)(sizeof(X) / sizeof((X)[0]))

/*
** Compute a string length that is limited to what can be stored in
** lower 30 bits of a 32-bit signed integer.
*/
static int strlen30(const char* z) {
  const char* z2 = z;
  while (*z2 != 0) {
    z2++;
  }
  return 0x3fffffff & static_cast<int>(z2 - z);
}

/*
** A callback for the sqlite3_log() interface.
*/
static void shellLog(void* pArg, int iErrCode, const char* zMsg) {
  auto* p = reinterpret_cast<struct callback_data*>(pArg);
  if (p->pLog == nullptr) {
    return;
  }
  fprintf(p->pLog, "(%d) %s\n", iErrCode, zMsg);
  fflush(p->pLog);
}

/*
** Output the given string as a quoted according to C or TCL quoting rules.
*/
static void output_c_string(FILE* out, const char* z) {
  unsigned int c;
  fputc('"', out);
  while ((c = *(z++)) != 0) {
    if (c == '\\') {
      fputc(c, out);
      fputc(c, out);
    } else if (c == '"') {
      fputc('\\', out);
      fputc('"', out);
    } else if (c == '\t') {
      fputc('\\', out);
      fputc('t', out);
    } else if (c == '\n') {
      fputc('\\', out);
      fputc('n', out);
    } else if (c == '\r') {
      fputc('\\', out);
      fputc('r', out);
    } else if (isprint(c & 0xff) == 0) {
      fprintf(out, R"(\%03o)", c & 0xff);
    } else {
      fputc(c, out);
    }
  }
  fputc('"', out);
}

/*
** If a field contains any character identified by a 1 in the following
** array, then the string must be quoted for CSV.
*/
static const char needCsvQuote[] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
};

/*
** Output a single term of CSV.  Actually, p->separator is used for
** the separator, which may or may not be a comma.  p->nullvalue is
** the null value.  Strings are quoted if necessary.
*/
static void output_csv(struct callback_data* p, const char* z, int bSep) {
  FILE* out = p->out;
  if (z == nullptr) {
    fprintf(out, "%s", p->nullvalue);
  } else {
    int i;
    int nSep = strlen30(p->separator);
    for (i = 0; z[i] != 0; i++) {
      if ((needCsvQuote[((unsigned char*)z)[i]] != 0) ||
          (z[i] == p->separator[0] &&
           (nSep == 1 || memcmp(z, p->separator, nSep) == 0))) {
        i = 0;
        break;
      }
    }
    if (i == 0) {
      putc('"', out);
      for (i = 0; z[i] != 0; i++) {
        if (z[i] == '"') {
          putc('"', out);
        }
        putc(z[i], out);
      }
      putc('"', out);
    } else {
      fprintf(out, "%s", z);
    }
  }
  if (bSep != 0) {
    fprintf(p->out, "%s", p->separator);
  }
}

#ifdef SIGINT
/*
** This routine runs when the user presses Ctrl-C
*/
static void interrupt_handler(int signal) {
  if (signal == SIGINT) {
    seenInterrupt = 1;
  }
}
#endif

/*
** This is the callback routine that the shell
** invokes for each row of a query result.
*/
static int shell_callback(void* pArg,
                          int nArg,
                          const char** azArg,
                          const char** azCol,
                          int* /*aiType*/) {
  int i;
  auto* p = reinterpret_cast<struct callback_data*>(pArg);

  switch (p->mode) {
  case MODE_Pretty: {
    if (p->prettyPrint->columns.empty()) {
      for (i = 0; i < nArg; i++) {
        p->prettyPrint->columns.push_back(std::string(azCol[i]));
      }
    }

    osquery::Row r;
    for (i = 0; i < nArg; ++i) {
      if (azCol[i] != nullptr) {
        r[std::string(azCol[i])] = (azArg[i] == nullptr)
                                       ? osquery::FLAGS_nullvalue
                                       : std::string(azArg[i]);
      }
    }
    osquery::computeRowLengths(r, p->prettyPrint->lengths);
    p->prettyPrint->results.push_back(r);
    break;
  }
  case MODE_Line: {
    int w = 5;
    if (azArg == nullptr) {
      break;
    }
    for (i = 0; i < nArg; i++) {
      int len = strlen30(azCol[i] != nullptr ? azCol[i] : "");
      if (len > w) {
        w = len;
      }
    }
    if (p->cnt++ > 0) {
      fprintf(p->out, "\n");
    }
    for (i = 0; i < nArg; i++) {
      fprintf(p->out,
              "%*s = %s\n",
              w,
              azCol[i],
              azArg[i] != nullptr ? azArg[i] : p->nullvalue);
    }
    break;
  }
  case MODE_Column: {
    if (p->cnt++ == 0) {
      for (i = 0; i < nArg; i++) {
        int w;
        if (i < ArraySize(p->colWidth)) {
          w = p->colWidth[i];
        } else {
          w = 0;
        }
        if (w == 0) {
          w = strlen30(azCol[i] != nullptr ? azCol[i] : "");
          if (w < 10) {
            w = 10;
          }
          int n = strlen30((azArg != nullptr) && (azArg[i] != nullptr)
                               ? azArg[i]
                               : p->nullvalue);
          if (w < n) {
            w = n;
          }
        }
        if (i < ArraySize(p->actualWidth)) {
          p->actualWidth[i] = w;
        }
        if (p->showHeader != 0) {
          if (w < 0) {
            fprintf(p->out,
                    "%*.*s%s",
                    -w,
                    -w,
                    azCol[i],
                    i == nArg - 1 ? "\n" : "  ");
          } else {
            fprintf(p->out,
                    "%-*.*s%s",
                    w,
                    w,
                    azCol[i],
                    i == nArg - 1 ? "\n" : "  ");
          }
        }
      }
      if (p->showHeader != 0) {
        for (i = 0; i < nArg; i++) {
          int w;
          if (i < ArraySize(p->actualWidth)) {
            w = p->actualWidth[i];
            if (w < 0) {
              w = -w;
            }
          } else {
            w = 10;
          }
          fprintf(p->out,
                  "%-*.*s%s",
                  w,
                  w,
                  "-----------------------------------"
                  "----------------------------------------------------------",
                  i == nArg - 1 ? "\n" : "  ");
        }
      }
    }
    if (azArg == nullptr) {
      break;
    }
    for (i = 0; i < nArg; i++) {
      int w;
      if (i < ArraySize(p->actualWidth)) {
        w = p->actualWidth[i];
      } else {
        w = 10;
      }
      if (i == 1 && (p->aiIndent != nullptr) && (p->pStmt != nullptr)) {
        if (p->iIndent < p->nIndent) {
          fprintf(p->out, "%*.s", p->aiIndent[p->iIndent], "");
        }
        p->iIndent++;
      }
      if (w < 0) {
        fprintf(p->out,
                "%*.*s%s",
                -w,
                -w,
                azArg[i] != nullptr ? azArg[i] : p->nullvalue,
                i == nArg - 1 ? "\n" : "  ");
      } else {
        fprintf(p->out,
                "%-*.*s%s",
                w,
                w,
                azArg[i] != nullptr ? azArg[i] : p->nullvalue,
                i == nArg - 1 ? "\n" : "  ");
      }
    }
    break;
  }
  case MODE_Semi:
  case MODE_List: {
    if (p->cnt++ == 0 && (p->showHeader != 0)) {
      for (i = 0; i < nArg; i++) {
        fprintf(p->out, "%s%s", azCol[i], i == nArg - 1 ? "\n" : p->separator);
      }
    }
    if (azArg == nullptr) {
      break;
    }
    for (i = 0; i < nArg; i++) {
      const char* z = azArg[i];
      if (z == nullptr) {
        z = p->nullvalue;
      }
      fprintf(p->out, "%s", z);
      if (i < nArg - 1) {
        fprintf(p->out, "%s", p->separator);
      } else if (p->mode == MODE_Semi) {
        fprintf(p->out, ";\n");
      } else {
        fprintf(p->out, "\n");
      }
    }
    break;
  }
  case MODE_Csv: {
    if (p->cnt++ == 0 && (p->showHeader != 0)) {
      for (i = 0; i < nArg; i++) {
        output_csv(p,
                   azCol[i] != nullptr ? azCol[i] : "",
                   static_cast<int>(i < nArg - 1));
      }
      fprintf(p->out, "\n");
    }
    if (azArg == nullptr) {
      break;
    }
    for (i = 0; i < nArg; i++) {
      output_csv(p, azArg[i], static_cast<int>(i < nArg - 1));
    }
    fprintf(p->out, "\n");
    break;
  }
  }
  return 0;
}

/*
** Set the destination table field of the callback_data structure to
** the name of the table given.  Escape any quote characters in the
** table name.
*/
static void set_table_name(struct callback_data* p, const char* zName) {
  int i, n;
  int needQuote;
  char* z;

  if (p->zDestTable != nullptr) {
    free(p->zDestTable);
    p->zDestTable = nullptr;
  }

  if (zName == nullptr) {
    return;
  }

  needQuote = static_cast<int>(
      (isalpha(static_cast<unsigned char>(*zName)) == 0) && *zName != '_');
  for (i = n = 0; zName[i] != 0; i++, n++) {
    if ((isalnum(static_cast<unsigned char>(zName[i])) == 0) &&
        zName[i] != '_') {
      needQuote = 1;
      if (zName[i] == '\'') {
        n++;
      }
    }
  }
  if (needQuote != 0) {
    n += 2;
  }
  z = p->zDestTable = reinterpret_cast<char*>(malloc(n + 1));
  if (z == nullptr) {
    fprintf(stderr, "Error: out of memory\n");
    exit(1);
  }
  n = 0;
  if (needQuote != 0) {
    z[n++] = '\'';
  }
  for (i = 0; zName[i] != 0; i++) {
    z[n++] = zName[i];
    if (zName[i] == '\'') {
      z[n++] = '\'';
    }
  }
  if (needQuote != 0) {
    z[n++] = '\'';
  }
  z[n] = 0;
}

static void pretty_print_if_needed(struct callback_data* pArg) {
  if ((pArg != nullptr) && pArg->mode == MODE_Pretty) {
    if (osquery::FLAGS_json_pretty) {
      osquery::jsonPrettyPrint(pArg->prettyPrint->results);
    } else if (osquery::FLAGS_json) {
      osquery::jsonPrint(pArg->prettyPrint->results);
    } else {
      osquery::prettyPrint(pArg->prettyPrint->results,
                           pArg->prettyPrint->columns,
                           pArg->prettyPrint->lengths);
    }
    pArg->prettyPrint->results.clear();
    pArg->prettyPrint->columns.clear();
    pArg->prettyPrint->lengths.clear();
  }
}

/*
** Allocate space and save off current error string.
*/
static char* save_err_msg(sqlite3* db) {
  int nErrMsg = 1 + strlen30(sqlite3_errmsg(db));
  auto* zErrMsg = reinterpret_cast<char*>(sqlite3_malloc(nErrMsg));
  if (zErrMsg != nullptr) {
    memcpy(zErrMsg, sqlite3_errmsg(db), nErrMsg);
  }
  return zErrMsg;
}

static int shell_exec_remote(
    const char* zSql, /* SQL to be evaluated */
    int (*xCallback)(
        void*, int, const char**, const char**, int*), /* Callback function */
    /* (not the same as sqlite3_exec) */
    struct callback_data* pArg, /* Pointer to struct callback_data */
    char** pzErrMsg /* Error msg written here */
) {
  osquery::QueryData qd, types;

  auto setError = [](char** pzErrMsg, const osquery::Status& s) {
    const auto msg = s.getMessage();
    auto* zErrMsg = reinterpret_cast<char*>(sqlite3_malloc(msg.size() + 1));
    if (zErrMsg != nullptr) {
      memset(zErrMsg, 0, msg.size() + 1);
      memcpy(zErrMsg, msg.c_str(), msg.size());
    }
    *pzErrMsg = zErrMsg;
  };

  try {
    osquery::ExtensionManagerClient client(osquery::FLAGS_connect);
    auto s = client.query(zSql, qd);
    if (!s.ok()) {
      setError(pzErrMsg, s);
      return s.getCode();
    }

    // Extract the correct column order.
    s = client.getQueryColumns(zSql, types);
    if (!s.ok()) {
      setError(pzErrMsg, s);
      return s.getCode();
    }
  } catch (const std::exception& e) {
    auto s = osquery::Status::failure("Extension call failed: " +
                                      std::string(e.what()));
    setError(pzErrMsg, s);
    return s.getCode();
  }

  for (const auto& r : qd) {
    std::vector<const char*> columns;
    std::vector<const char*> values;
    for (const auto& col : types) {
      auto val = r.find(col.begin()->first);
      if (val != r.end()) {
        values.push_back(val->second.c_str());
        columns.push_back(val->first.c_str());
      }
    }
    xCallback(pArg, r.size(), &values[0], &columns[0], nullptr);
  }

  pretty_print_if_needed(pArg);
  return 0;
}

/*
** Execute a statement or set of statements.  Print
** any result rows/columns depending on the current mode
** set via the supplied callback.
**
** This is very similar to SQLite's built-in sqlite3_exec()
** function except it takes a slightly different callback
** and callback data argument.
*/
static int shell_exec(
    const char* zSql, /* SQL to be evaluated */
    int (*xCallback)(
        void*, int, const char**, const char**, int*), /* Callback function */
    /* (not the same as sqlite3_exec) */
    struct callback_data* pArg, /* Pointer to struct callback_data */
    char** pzErrMsg /* Error msg written here */
) {
  if (!osquery::FLAGS_connect.empty()) {
    return shell_exec_remote(zSql, xCallback, pArg, pzErrMsg);
  }

  // Grab a lock on the managed DB instance.
  auto dbc = osquery::SQLiteDBManager::get();
  auto db = dbc->db();

  sqlite3_stmt* pStmt = nullptr; /* Statement to execute. */
  int rc = SQLITE_OK; /* Return Code */
  int rc2;
  const char* zLeftover; /* Tail of unprocessed SQL */

  if (pzErrMsg != nullptr) {
    *pzErrMsg = nullptr;
  }

  while ((zSql[0] != 0) && (SQLITE_OK == rc)) {
    auto lock(dbc->attachLock());

    /* A lock for attaching virtual tables, but also the SQL object states. */
    rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, &zLeftover);
    if (SQLITE_OK != rc) {
      if (pzErrMsg != nullptr) {
        *pzErrMsg = save_err_msg(db);
      }
    } else {
      if (pStmt == nullptr) {
        /* this happens for a comment or white-space */
        zSql = zLeftover;
        while (IsSpace(zSql[0])) {
          zSql++;
        }
        continue;
      }

      /* save off the prepared statement handle and reset row count */
      if (pArg != nullptr) {
        pArg->pStmt = pStmt;
        pArg->cnt = 0;
      }

      /* echo the sql statement if echo on */
      if ((pArg != nullptr) && (pArg->echoOn != 0)) {
        const char* zStmtSql = sqlite3_sql(pStmt);
        fprintf(pArg->out, "%s\n", zStmtSql != nullptr ? zStmtSql : zSql);
      }

      /* perform the first step.  this will tell us if we
      ** have a result set or not and how wide it is.
      */
      rc = sqlite3_step(pStmt);
      /* if we have a result set... */
      if (SQLITE_ROW == rc) {
        /* if we have a callback... */
        if (xCallback != nullptr) {
          /* allocate space for col name ptr, value ptr, and type */
          int nCol = sqlite3_column_count(pStmt);
          void* pData = sqlite3_malloc(3 * nCol * sizeof(const char*) + 1);
          if (pData == nullptr) {
            rc = SQLITE_NOMEM;
          } else {
            const auto** azCols = reinterpret_cast<const char**>(
                pData); /* Names of result columns */
            const char** azVals = &azCols[nCol]; /* Results */
            auto* aiTypes =
                reinterpret_cast<int*>(&azVals[nCol]); /* Result types */
            int i;
            assert(sizeof(int) <= sizeof(char*));
            /* save off ptrs to column names */
            for (i = 0; i < nCol; i++) {
              azCols[i] = const_cast<char*>(sqlite3_column_name(pStmt, i));
            }
            do {
              /* extract the data and data types */
              for (i = 0; i < nCol; i++) {
                aiTypes[i] = sqlite3_column_type(pStmt, i);
                azVals[i] = (char*)sqlite3_column_text(pStmt, i);
                if ((azVals[i] == nullptr) && (aiTypes[i] != SQLITE_NULL)) {
                  rc = SQLITE_NOMEM;
                  break; /* from for */
                }
              } /* end for */

              /* if data and types extracted successfully... */
              if (SQLITE_ROW == rc) {
                /* call the supplied callback with the result row data */
                if (xCallback(pArg, nCol, azVals, azCols, aiTypes) != 0) {
                  rc = SQLITE_ABORT;
                } else {
                  rc = sqlite3_step(pStmt);
                }
              }
            } while (SQLITE_ROW == rc);
            sqlite3_free(pData);
          }
        } else {
          do {
            rc = sqlite3_step(pStmt);
          } while (rc == SQLITE_ROW);
        }
      }

      /* Finalize the statement just executed. If this fails, save a
      ** copy of the error message. Otherwise, set zSql to point to the
      ** next statement to execute. */
      rc2 = sqlite3_finalize(pStmt);
      if (rc != SQLITE_NOMEM) {
        rc = rc2;
      }
      if (rc == SQLITE_OK) {
        zSql = zLeftover;
        while (IsSpace(zSql[0])) {
          zSql++;
        }
      } else if (pzErrMsg != nullptr) {
        *pzErrMsg = save_err_msg(db);
      }

      /* clear saved stmt handle */
      if (pArg != nullptr) {
        pArg->pStmt = nullptr;
      }
    }
  } /* end while */
  dbc->clearAffectedTables();

  pretty_print_if_needed(pArg);

  return rc;
}

/* Forward reference */
static int process_input(struct callback_data* p, FILE* in);

/*
** Do C-language style dequoting.
**
**    \t    -> tab
**    \n    -> newline
**    \r    -> carriage return
**    \"    -> "
**    \NNN  -> ascii character NNN in octal
**    \\    -> backslash
*/
static void resolve_backslashes(char* z) {
  int i, j;
  char c;
  for (i = j = 0; (c = z[i]) != 0; i++, j++) {
    if (c == '\\') {
      c = z[++i];
      if (c == 'n') {
        c = '\n';
      } else if (c == 't') {
        c = '\t';
      } else if (c == 'r') {
        c = '\r';
      } else if (c == '\\') {
        c = '\\';
      } else if (c >= '0' && c <= '7') {
        c -= '0';
        if (z[i + 1] >= '0' && z[i + 1] <= '7') {
          i++;
          c = (c << 3) + z[i] - '0';
          if (z[i + 1] >= '0' && z[i + 1] <= '7') {
            i++;
            c = (c << 3) + z[i] - '0';
          }
        }
      }
    }
    z[j] = c;
  }
  z[j] = 0;
}

/*
** Return the value of a hexadecimal digit.  Return -1 if the input
** is not a hex digit.
*/
static int hexDigitValue(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

/*
** Interpret zArg as an integer value, possibly with suffixes.
*/
static sqlite3_int64 integerValue(const char* zArg) {
  sqlite3_int64 v = 0;
  static const struct {
    char* zSuffix;
    int iMult;
  } aMult[] = {
      {(char*)"KiB", 1024},
      {(char*)"MiB", 1024 * 1024},
      {(char*)"GiB", 1024 * 1024 * 1024},
      {(char*)"KB", 1000},
      {(char*)"MB", 1000000},
      {(char*)"GB", 1000000000},
      {(char*)"K", 1000},
      {(char*)"M", 1000000},
      {(char*)"G", 1000000000},
  };
  int i;
  int isNeg = 0;
  if (zArg[0] == '-') {
    isNeg = 1;
    zArg++;
  } else if (zArg[0] == '+') {
    zArg++;
  }
  if (zArg[0] == '0' && zArg[1] == 'x') {
    int x;
    zArg += 2;
    while ((x = hexDigitValue(zArg[0])) >= 0) {
      v = (v << 4) + x;
      zArg++;
    }
  } else {
    while (IsDigit(zArg[0])) {
      v = v * 10 + zArg[0] - '0';
      zArg++;
    }
  }
  for (i = 0; i < ArraySize(aMult); i++) {
    if (sqlite3_stricmp(aMult[i].zSuffix, zArg) == 0) {
      v *= aMult[i].iMult;
      break;
    }
  }
  return isNeg != 0 ? -v : v;
}

/*
** Interpret zArg as either an integer or a boolean value.  Return 1 or 0
** for TRUE and FALSE.  Return the integer value if appropriate.
*/
static int booleanValue(char* zArg) {
  int i;
  if (zArg[0] == '0' && zArg[1] == 'x') {
    for (i = 2; hexDigitValue(zArg[i]) >= 0; i++) {
    }
  } else {
    for (i = 0; zArg[i] >= '0' && zArg[i] <= '9'; i++) {
    }
  }
  if (i > 0 && zArg[i] == 0) {
    return static_cast<int>(integerValue(zArg) & 0xffffffff);
  }
  auto expected = osquery::tryTo<bool>(std::string{zArg});
  if (expected.isError()) {
    fprintf(
        stderr, "ERROR: Not a boolean value: \"%s\". Assuming \"no\".\n", zArg);
  }
  return expected.takeOr(false) ? 1 : 0;
}

inline void meta_tables(int nArg, char** azArg) {
  auto tables = osquery::RegistryFactory::get().names("table");
  std::sort(tables.begin(), tables.end());
  for (const auto& table_name : tables) {
    if (nArg == 1 || table_name.find(azArg[1]) == 0) {
      printf("  => %s\n", table_name.c_str());
    }
  }
}

inline void meta_types(struct callback_data* pArg, char* zSql) {
  const char* COLUMN_NAMES[] = {"name", "type"};

  auto dbc = osquery::SQLiteDBManager::get();
  osquery::TableColumns columns;
  auto status = getQueryColumnsInternal(zSql, columns, dbc);

  if (status.ok()) {
    for (const auto& column_info : columns) {
      const auto& name = std::get<0>(column_info);
      const auto& type = columnTypeName(std::get<1>(column_info));

      std::vector<const char*> row{{name.c_str(), type.c_str()}};

      shell_callback(pArg, 2, &row[0], COLUMN_NAMES, nullptr);
    }
    pretty_print_if_needed(pArg);
  } else {
    fprintf(
        stdout, "Error %d: %s\n", status.getCode(), status.toString().c_str());
  }
}

inline void meta_schema(int nArg, char** azArg) {
  for (const auto& table : osquery::RegistryFactory::get().names("table")) {
    if (nArg > 1 && table.find(azArg[1]) != 0) {
      continue;
    }

    osquery::PluginResponse response;
    auto status = osquery::Registry::call(
        "table", table, {{"action", "columns"}}, response);
    if (status.ok()) {
      auto const aliases = true;
      auto const is_extension = false;

      fprintf(
          stdout,
          "CREATE TABLE %s%s;\n",
          table.c_str(),
          osquery::columnDefinition(response, aliases, is_extension).c_str());
    }
  }
}

inline void meta_features(struct callback_data* p) {
  auto results = osquery::SQL(
      "select * from osquery_flags where (name like 'disable_%' or name like "
      "'enable_%') and type = 'bool'");
  for (const auto& flag : results.rows()) {
    fprintf(
        p->out, "%s: %s\n", flag.at("name").c_str(), flag.at("value").c_str());
  }
}

inline void meta_version(struct callback_data* p) {
  fprintf(p->out, "osquery %s\n", osquery::kVersion.c_str());
  fprintf(p->out, "using SQLite %s\n", sqlite3_libversion());
}

inline void meta_show(struct callback_data* p) {
  // The show/summary meta command is provided to help with general
  // debugging.  All of this information is 'duplicate', and can be
  // found with better detail within osquery virtual tables.
  print_bold("osquery");
  printf(
      " - being built, with love.\n"
      "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
  meta_version(p);

  fprintf(p->out, "\nGeneral settings:\n");
  fprintf(p->out, "%13.13s: %s\n", "Flagfile", FLAGS_flagfile.c_str());
  // Show helpful config-related settings.
  fprintf(
      p->out, "%13.13s: %s", "Config", osquery::FLAGS_config_plugin.c_str());
  if (osquery::FLAGS_config_plugin == "filesystem") {
    fprintf(p->out, " (%s)\n", osquery::FLAGS_config_path.c_str());
  } else if (osquery::FLAGS_config_plugin == "tls") {
    fprintf(p->out,
            " (%s%s)\n",
            osquery::FLAGS_tls_hostname.c_str(),
            osquery::FLAGS_config_tls_endpoint.c_str());
  } else {
    fprintf(p->out, "\n");
  }

  // Show helpful logger-related settings.
  fprintf(
      p->out, "%13.13s: %s", "Logger", osquery::FLAGS_logger_plugin.c_str());
  if (osquery::FLAGS_logger_plugin == "filesystem") {
    fprintf(p->out, " (%s)\n", osquery::FLAGS_logger_path.c_str());
  } else if (osquery::FLAGS_logger_plugin == "tls") {
    fprintf(p->out,
            " (%s%s)\n",
            osquery::FLAGS_tls_hostname.c_str(),
            osquery::FLAGS_logger_tls_endpoint.c_str());
  } else {
    fprintf(p->out, "\n");
  }

  fprintf(p->out,
          "%13.13s: %s\n",
          "Distributed",
          osquery::FLAGS_distributed_plugin.c_str());

  auto database = osquery::RegistryFactory::get().getActive("database");
  fprintf(p->out, "%13.13s: %s", "Database", database.c_str());
  if (database == "rocksdb") {
    fprintf(p->out, " (%s)\n", osquery::FLAGS_database_path.c_str());
  } else {
    fprintf(p->out, "\n");
  }

  {
    auto results = osquery::SQL::selectAllFrom("osquery_extensions");
    std::vector<std::string> extensions;
    for (const auto& extension : results) {
      extensions.push_back(extension.at("name"));
    }
    fprintf(p->out,
            "%13.13s: %s\n",
            "Extensions",
            osquery::join(extensions, ", ").c_str());

    fprintf(p->out,
            "%13.13s: %s\n",
            "Socket",
            osquery::FLAGS_extensions_socket.c_str());
  }

  fprintf(p->out, "\nShell settings:\n");
  fprintf(p->out, "%13.13s: %s\n", "echo", p->echoOn != 0 ? "on" : "off");
  fprintf(
      p->out, "%13.13s: %s\n", "headers", p->showHeader != 0 ? "on" : "off");
  fprintf(p->out, "%13.13s: %s\n", "mode", modeDescr[p->mode]);
  fprintf(p->out, "%13.13s: ", "nullvalue");
  output_c_string(p->out, p->nullvalue);
  fprintf(p->out, "\n");
  fprintf(p->out,
          "%13.13s: %s\n",
          "output",
          strlen30(p->outfile) != 0 ? p->outfile : "stdout");
  fprintf(p->out, "%13.13s: ", "separator");
  output_c_string(p->out, p->separator);
  fprintf(p->out, "\n");
  fprintf(p->out, "%13.13s: ", "width");
  for (int i = 0; i < ArraySize(p->colWidth) && p->colWidth[i] != 0; i++) {
    fprintf(p->out, "%d ", p->colWidth[i]);
  }
  fprintf(p->out, "\n");

  {
    fprintf(p->out, "\nNon-default flags/options:\n");
    auto results = osquery::SQL(
        "select * from osquery_flags where default_value <> value");
    for (const auto& flag : results.rows()) {
      fprintf(p->out,
              "  %s: %s\n",
              flag.at("name").c_str(),
              flag.at("value").c_str());
    }
  }
}

/*
** If an input line begins with "." then invoke this routine to
** process that line.
**
** Return 1 on error, 2 to exit, and 0 otherwise.
*/
static int do_meta_command(char* zLine, struct callback_data* p) {
  int i = 1;
  int nArg = 0;
  int n, c;
  int rc = 0;
  char* azArg[50];

  /* Parse the input line into tokens.
   */
  while ((zLine[i] != 0) && nArg < ArraySize(azArg)) {
    while (IsSpace(zLine[i])) {
      i++;
    }
    if (zLine[i] == 0) {
      break;
    }
    if (zLine[i] == '\'' || zLine[i] == '"') {
      int delim = zLine[i++];
      azArg[nArg++] = &zLine[i];
      while ((zLine[i] != 0) && zLine[i] != delim) {
        if (zLine[i] == '\\' && delim == '"' && zLine[i + 1] != 0) {
          i++;
        }
        i++;
      }
      if (zLine[i] == delim) {
        zLine[i++] = 0;
      }
      if (delim == '"') {
        resolve_backslashes(azArg[nArg - 1]);
      }
    } else {
      azArg[nArg++] = &zLine[i];
      while ((zLine[i] != 0) && !IsSpace(zLine[i])) {
        i++;
      }
      if (zLine[i] != 0) {
        zLine[i++] = 0;
      }
      resolve_backslashes(azArg[nArg - 1]);
    }
  }

  /* Process the input line.
   */
  if (nArg == 0) {
    return 0; /* no tokens, no error */
  }
  n = strlen30(azArg[0]);
  c = azArg[0][0];
  if (c == 'a' && strncmp(azArg[0], "all", n) == 0 && nArg == 2) {
    struct callback_data data {};
    memcpy(&data, p, sizeof(data));
    auto query = std::string("SELECT * FROM ") + azArg[1];
    rc = shell_exec(query.c_str(), shell_callback, &data, nullptr);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error querying table: %s\n", azArg[1]);
    }
    return rc;
  }

  if (c == 's' && strncmp(azArg[0], "socket", n) == 0 && nArg == 1) {
    fprintf(p->out, "%s", osquery::FLAGS_extensions_socket.c_str());
    if (!osquery::FLAGS_connect.empty()) {
      fprintf(p->out, " (connected to %s)", osquery::FLAGS_connect.c_str());
    }
    fprintf(p->out, "\n");
    return rc;
  }

  if (c == 'c' && strncmp(azArg[0], "connect", n) == 0 && nArg == 2) {
    if (osquery::FLAGS_connect.empty()) {
      osquery::FLAGS_connect = azArg[1];
      connect_socket();
      return rc;
    } else {
      fprintf(stderr, "Error: Please disconnect from the current socket\n");
      return 1;
    }
  }
  if (c == 'd' && strncmp(azArg[0], "disconnect", n) == 0 && nArg == 1) {
    if (!osquery::FLAGS_connect.empty()) {
      disconnect_socket();
      osquery::FLAGS_connect = "";
      return rc;
    } else {
      fprintf(stderr, "Error: Not connected to a socket\n");
      return 1;
    }
  }

  // A meta command may act on the database, grab a lock and instance.
  auto dbc = osquery::SQLiteDBManager::get();
  auto db = dbc->db();

  if (c == 'b' && n >= 3 && strncmp(azArg[0], "bail", n) == 0 && nArg > 1 &&
      nArg < 3) {
    bail_on_error = booleanValue(azArg[1]);
  } else if (c == 'e' && strncmp(azArg[0], "echo", n) == 0 && nArg > 1 &&
             nArg < 3) {
    p->echoOn = booleanValue(azArg[1]);
  } else if (c == 'e' && strncmp(azArg[0], "exit", n) == 0) {
    if (nArg > 1 && (rc = static_cast<int>(integerValue(azArg[1]))) != 0) {
      exit(rc);
    }
    rc = 2;
  } else if (c == 'f' && strncmp(azArg[0], "features", n) == 0 && nArg == 1) {
    meta_features(p);
  } else if (c == 'h' &&
             (strncmp(azArg[0], "header", n) == 0 ||
              strncmp(azArg[0], "headers", n) == 0) &&
             nArg > 1 && nArg < 3) {
    p->showHeader = booleanValue(azArg[1]);
  } else if (c == 'h' && strncmp(azArg[0], "help", n) == 0) {
    fprintf(stderr, "%s", zHelp);
    if (HAS_TIMER) {
      fprintf(stderr, "%s", zTimerHelp);
    }
  } else if (c == 'm' && strncmp(azArg[0], "mode", n) == 0 && nArg == 2) {
    int n2 = strlen30(azArg[1]);
    if ((n2 == 4 && strncmp(azArg[1], "line", n2) == 0) ||
        (n2 == 5 && strncmp(azArg[1], "lines", n2) == 0)) {
      p->mode = MODE_Line;
    } else if ((n2 == 6 && strncmp(azArg[1], "column", n2) == 0) ||
               (n2 == 7 && strncmp(azArg[1], "columns", n2) == 0)) {
      p->mode = MODE_Column;
    } else if (n2 == 4 && strncmp(azArg[1], "list", n2) == 0) {
      p->mode = MODE_List;
    } else if (n2 == 6 && strncmp(azArg[1], "pretty", n2) == 0) {
      p->mode = MODE_Pretty;
    } else if (n2 == 3 && strncmp(azArg[1], "csv", n2) == 0) {
      p->mode = MODE_Csv;
      sqlite3_snprintf(sizeof(p->separator), p->separator, ",");
    } else {
      fprintf(stderr,
              "Error: mode should be one of: "
              "column csv line list pretty\n");
      rc = 1;
    }
  } else if (c == 'n' && strncmp(azArg[0], "nullvalue", n) == 0 && nArg == 2) {
    sqlite3_snprintf(sizeof(p->nullvalue),
                     p->nullvalue,
                     "%.*s",
                     ArraySize(p->nullvalue) - 1,
                     azArg[1]);
  } else if (c == 'p' && n >= 3 && strncmp(azArg[0], "print", n) == 0) {
    int j;
    for (j = 1; j < nArg; j++) {
      if (j > 1) {
        fprintf(p->out, " ");
      }
      fprintf(p->out, "%s", azArg[j]);
    }
    fprintf(p->out, "\n");
  } else if (c == 'q' && strncmp(azArg[0], "quit", n) == 0 && nArg == 1) {
    rc = 2;
  } else if (c == 's' && strncmp(azArg[0], "schema", n) == 0 && nArg < 3) {
    meta_schema(nArg, azArg);
  } else if (c == 's' && strncmp(azArg[0], "separator", n) == 0 && nArg == 2) {
    sqlite3_snprintf(sizeof(p->separator),
                     p->separator,
                     "%.*s",
                     static_cast<int>(sizeof(p->separator)) - 1,
                     azArg[1]);
  } else if (c == 's' &&
             (strncmp(azArg[0], "show", n) == 0 ||
              strncmp(azArg[0], "summary", n) == 0) &&
             nArg == 1) {
    meta_show(p);
  } else if (c == 't' && n > 1 && strncmp(azArg[0], "tables", n) == 0 &&
             nArg < 3) {
    meta_tables(nArg, azArg);
  } else if (c == 'l' && n > 1 && strncmp(azArg[0], "list", n) == 0 &&
             nArg < 3) {
    meta_tables(nArg, azArg);
  } else if (c == 't' && n > 4 && strncmp(azArg[0], "timeout", n) == 0 &&
             nArg == 2) {
    sqlite3_busy_timeout(db, static_cast<int>(integerValue(azArg[1])));
  } else if (HAS_TIMER && c == 't' && n >= 5 &&
             strncmp(azArg[0], "timer", n) == 0 && nArg == 2) {
    enableTimer = booleanValue(azArg[1]);
  } else if (c == 'v' && strncmp(azArg[0], "version", n) == 0) {
    meta_version(p);
  } else if (c == 'w' && strncmp(azArg[0], "width", n) == 0 && nArg > 1) {
    int j;
    assert(nArg <= ArraySize(azArg));
    for (j = 1; j < nArg && j < ArraySize(p->colWidth); j++) {
      p->colWidth[j - 1] = static_cast<int>(integerValue(azArg[j]));
    }
  } else {
    fprintf(stderr,
            "Error: unknown command or invalid arguments: "
            " \"%s\". Enter \".help\" for help\n",
            azArg[0]);
    rc = 1;
  }

  return rc;
}

/*
** Return TRUE if a semicolon occurs anywhere in the first N characters
** of string z[].
*/
static int line_contains_semicolon(const char* z, int N) {
  if (z == nullptr) {
    return 0;
  }

  for (int i = 0; i < N; i++) {
    if (z[i] == ';') {
      return 1;
    }
  }
  return 0;
}

/*
** Test to see if a line consists entirely of whitespace.
*/
static int _all_whitespace(const char* z) {
  if (z == nullptr) {
    return 0;
  }

  for (; *z != 0; z++) {
    if (IsSpace(z[0])) {
      continue;
    }

    if (*z == '/' && z[1] == '*') {
      z += 2;
      while ((*z != 0) && (*z != '*' || z[1] != '/')) {
        z++;
      }
      if (*z == 0) {
        return 0;
      }
      z++;
      continue;
    }
    if (*z == '-' && z[1] == '-') {
      z += 2;
      while ((*z != 0) && *z != '\n') {
        z++;
      }
      if (*z == 0) {
        return 1;
      }
      continue;
    }
    return 0;
  }
  return 1;
}

/*
** Read input from *in and process it.  If *in==0 then input
** is interactive - the user is typing it it.  Otherwise, input
** is coming from a file or device.  A prompt is issued and history
** is saved only if input is interactive.  An interrupt signal will
** cause this routine to exit immediately, unless input is interactive.
**
** Return the number of errors.
*/
static int process_input(struct callback_data* p, FILE* in) {
  /* A single input line */
  char* zLine = nullptr;

  /* Accumulated SQL text */
  char* zSql = nullptr;

  /* Error message returned */
  char* zErrMsg = nullptr;

  int nLine = 0; /* Length of current line */
  int nSql = 0; /* Bytes of zSql[] used */
  int nAlloc = 0; /* Allocated zSql[] space */
  int nSqlPrior = 0; /* Bytes of zSql[] used by prior line */
  int rc = 0; /* Error code */
  int errCnt = 0; /* Number of errors seen */
  int lineno = 0; /* Current line number */
  int startline = 0; /* Line number for start of current input */
  bool typesQuery = false;

  while (errCnt == 0 || (bail_on_error == 0) ||
         (in == nullptr && stdin_is_interactive)) {
    fflush(p->out);
    zLine = one_input_line(in, zLine, static_cast<int>(nSql > 0));
    if (zLine == nullptr) {
      /* End of input */
      if (stdin_is_interactive) {
        printf("\n");
      }
      break;
    }
    if (seenInterrupt != 0) {
      if (in != nullptr) {
        break;
      }
      seenInterrupt = 0;
    }
    lineno++;
    if (nSql == 0 && (_all_whitespace(zLine) != 0)) {
      if (p->echoOn != 0) {
        printf("%s\n", zLine);
      }
      continue;
    }
    if (zLine != nullptr && zLine[0] == '.' && nSql == 0) {
      if (p->echoOn != 0) {
        printf("%s\n", zLine);
      }
      if (strncmp(zLine, ".types ", 7) == 0) {
        typesQuery = true;
      } else {
        rc = do_meta_command(zLine, p);
        if (rc == 2) { /* exit requested */
          break;
        } else if (rc != 0) {
          errCnt++;
        }
        continue;
      }
    }
    nLine = strlen30(zLine);
    if (nSql + nLine + 2 >= nAlloc) {
      nAlloc = nSql + nLine + 100;
      auto qSql = reinterpret_cast<char*>(realloc(zSql, nAlloc));
      if (qSql == nullptr) {
        fprintf(stderr, "Error: out of memory\n");
        if (zSql != nullptr) {
          free(zSql);
        }
        exit(1);
      } else {
        zSql = qSql;
      }
    }
    nSqlPrior = nSql;
    if (nSql == 0) {
      int i;
      for (i = typesQuery ? 7 : 0; (zLine[i] != 0) && IsSpace(zLine[i]); i++) {
      }
      assert(nAlloc > 0 && zSql != nullptr);
      if (zSql != nullptr) {
        memcpy(zSql, zLine + i, nLine + 1 - i);
      }
      startline = lineno;
      nSql = nLine - i;
    } else {
      zSql[nSql++] = '\n';
      memcpy(zSql + nSql, zLine, nLine + 1);
      nSql += nLine;
    }
    if ((nSql != 0) &&
        (line_contains_semicolon(&zSql[nSqlPrior], nSql - nSqlPrior) != 0) &&
        (sqlite3_complete(zSql) != 0)) {
      if (typesQuery) {
        meta_types(p, zSql);
        typesQuery = false;
      } else {
        p->cnt = 0;
        BEGIN_TIMER;
        rc = shell_exec(zSql, shell_callback, p, &zErrMsg);
        END_TIMER;
        if ((rc != 0) || zErrMsg != nullptr) {
          char zPrefix[100] = {0};
          if (in != nullptr || !stdin_is_interactive) {
            sqlite3_snprintf(
                sizeof(zPrefix), zPrefix, "Error: near line %d:", startline);
          } else {
            sqlite3_snprintf(sizeof(zPrefix), zPrefix, "Error:");
          }
          if (zErrMsg != nullptr) {
            fprintf(stderr, "%s %s\n", zPrefix, zErrMsg);
            sqlite3_free(zErrMsg);
            zErrMsg = nullptr;
          }
          errCnt++;
        }
      }
      nSql = 0;
    } else if ((nSql != 0) && (_all_whitespace(zSql) != 0)) {
      if (p->echoOn != 0) {
        printf("%s\n", zSql);
      }
      nSql = 0;
    }
  }

  if (nSql != 0) {
    if (_all_whitespace(zSql) == 0) {
      fprintf(stderr, "Error: incomplete SQL: %s\n", zSql);
    }
  }
  if (zSql != nullptr) {
    free(zSql);
  }

  free(zLine);
  return static_cast<int>(errCnt > 0);
}

/*
** Initialize the state information in data
*/
static void main_init(struct callback_data* data) {
  memset(data, 0, sizeof(struct callback_data));
  data->prettyPrint = new struct prettyprint_data();
  data->mode = MODE_Pretty;
  data->showHeader = 1;
  data->separator[0] = '|';

  sqlite3_config(SQLITE_CONFIG_URI, 1);
  sqlite3_config(SQLITE_CONFIG_LOG, shellLog, data);

  auto term = osquery::getEnvVar("TERM");
  if (term.is_initialized() &&
      (*term).find("xterm-256color") != std::string::npos) {
    sqlite3_snprintf(
        sizeof(mainPrompt), mainPrompt, "\033[38;5;147mosquery> \033[0m");
    sqlite3_snprintf(sizeof(continuePrompt),
                     continuePrompt,
                     "\033[38;5;147m    ...> \033[0m");
  } else {
    sqlite3_snprintf(sizeof(mainPrompt), mainPrompt, "osquery> ");
    sqlite3_snprintf(sizeof(continuePrompt), continuePrompt, "    ...> ");
  }
  sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
}

namespace osquery {

void tableCompletionFunction(char const* prefix, linenoiseCompletions* lc) {
  auto tables = osquery::RegistryFactory::get().names("table");
  size_t index = 0;

  while (index < tables.size()) {
    const std::string& table = tables.at(index);
    ++index;

    if (boost::algorithm::starts_with(table, prefix)) {
      linenoiseAddCompletion(lc, table.c_str());
    }
  }
}

int runQuery(struct callback_data* data, const char* query) {
  char* error = nullptr;
  int rc = shell_exec(query, shell_callback, data, &error);
  if (error != nullptr) {
    fprintf(stderr, "Error: %s\n", error);
    rc = (rc == 0) ? 1 : rc;
    sqlite3_free(error);
  } else if (rc != 0) {
    fprintf(stderr, "Error: unable to process SQL \"%s\"\n", query);
  }
  return rc;
}

int runPack(struct callback_data* data) {
  int rc = 0;

  // Check every pack for a name matching the requested --pack flag.
  Config::get().packs([data, &rc](const Pack& pack) {
    if (pack.getName() != FLAGS_pack) {
      return;
    }

    for (const auto& query : pack.getSchedule()) {
      rc = runQuery(data, query.second.query.c_str());
      if (rc != 0) {
        fprintf(stderr,
                "Could not execute query %s: %s\n",
                query.first.c_str(),
                query.second.query.c_str());
        return;
      }
    }
  });
  return rc;
}

int launchIntoShell(int argc, char** argv) {
  struct callback_data data {};
  main_init(&data);

#if defined(SQLITE_ENABLE_WHERETRACE)
  sqlite3WhereTrace = 0xffffffff;
#endif

  // Move the attach function method into the osquery SQL implementation.
  // This allow simple/straightforward control of concurrent DB access.
  osquery::attachFunctionInternal("shellstatic", shellstaticFunc);
  stdin_is_interactive = platformIsatty(stdin);

  // SQLite: Make sure we have a valid signal handler early
  signal(SIGINT, interrupt_handler);

  data.out = stdout;

  // Set modes and settings from CLI flags.
  data.showHeader = static_cast<int>(FLAGS_header);
  if (FLAGS_list) {
    data.mode = MODE_List;
  } else if (FLAGS_line) {
    data.mode = MODE_Line;
  } else if (FLAGS_csv) {
    data.mode = MODE_Csv;
    data.separator[0] = ',';
  } else {
    data.mode = MODE_Pretty;
  }

  sqlite3_snprintf(
      sizeof(data.separator), data.separator, "%s", FLAGS_separator.c_str());
  sqlite3_snprintf(
      sizeof(data.nullvalue), data.nullvalue, "%s", FLAGS_nullvalue.c_str());

  int rc = 0;
  if (!FLAGS_connect.empty()) {
    connect_socket();
  }

  if (FLAGS_L || !FLAGS_A.empty()) {
    // Helper meta commands from shell switches.
    std::string query = (FLAGS_L) ? ".tables" : ".all " + FLAGS_A;
    auto* cmd = new char[query.size() + 1];
    memset(cmd, 0, query.size() + 1);
    std::copy(query.begin(), query.end(), cmd);
    rc = do_meta_command(cmd, &data);
    delete[] cmd;
  } else if (!FLAGS_pack.empty()) {
    rc = runPack(&data);
  } else if (argc > 1 && argv[1] != nullptr) {
    // Run a command or statement from CLI
    char* query = argv[1];
    if (query[0] == '.') {
      rc = do_meta_command(query, &data);
      rc = (rc == 2) ? 0 : rc;
    } else {
      rc = runQuery(&data, query);
      if (rc != 0) {
        if (data.prettyPrint != nullptr) {
          delete data.prettyPrint;
        }
        return rc;
      }
    }
  } else {
    // Run commands received from standard input
    if (stdin_is_interactive) {
#ifdef WIN32
      SetConsoleCP(CP_UTF8);
      SetConsoleOutputCP(CP_UTF8);
#endif // WIN32
      printf("Using a ");
      print_bold("virtual database");
      printf(". Need help, type '.help'\n");

      auto history_file =
          (fs::path(osquery::osqueryHomeDirectory()) / ".history")
              .make_preferred()
              .string();
      linenoiseHistorySetMaxLen(100);
      linenoiseHistoryLoad(history_file.c_str());
      linenoiseSetCompletionCallback(tableCompletionFunction);

      rc = process_input(&data, nullptr);

      linenoiseHistorySave(history_file.c_str());
    } else {
      rc = process_input(&data, stdin);
    }
  }

  set_table_name(&data, nullptr);

  if (data.prettyPrint != nullptr) {
    delete data.prettyPrint;
  }
  return rc;
}
} // namespace osquery
