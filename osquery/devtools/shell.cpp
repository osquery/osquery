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

#include <signal.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <sqlite3.h>

#include <boost/algorithm/string/predicate.hpp>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/flags.h>

#include "osquery/extensions/interface.h"
#include "osquery/devtools/devtools.h"
#include "osquery/sql/virtual_table.h"

namespace osquery {

/// Define flags used by the shell. They are parsed by the drop-in shell.
SHELL_FLAG(bool, csv, false, "Set output mode to 'csv'");
SHELL_FLAG(bool, json, false, "Set output mode to 'json'");
SHELL_FLAG(bool, line, false, "Set output mode to 'line'");
SHELL_FLAG(bool, list, false, "Set output mode to 'list'");
SHELL_FLAG(string, nullvalue, "", "Set string for NULL values, default ''");
SHELL_FLAG(string, separator, "|", "Set output field separator, default '|'");

/// Define short-hand shell switches.
SHELL_FLAG(bool, L, false, "List all table names");
SHELL_FLAG(string, A, "", "Select all from a table");
}

/*
** Text of a help message
*/
static char zHelp[] =
    "Welcome to the osquery shell. Please explore your OS!\n"
    "You are connected to a transient 'in-memory' virtual database.\n"
    "\n"
    ".all [TABLE]       Select all from a table\n"
    ".bail ON|OFF       Stop after hitting an error; default OFF\n"
    ".daemonconnect     Daemon executes queries on behalf of the shell.\n"
    ".disconnect        Disconnect from the daemon.\n"
    ".echo ON|OFF       Turn command echo on or off\n"
    ".exit              Exit this program\n"
    ".header(s) ON|OFF  Turn display of headers on or off\n"
    ".help              Show this message\n"
    ".mode MODE         Set output mode where MODE is one of:\n"
    "                     csv      Comma-separated values\n"
    "                     column   Left-aligned columns.  (See .width)\n"
    "                     line     One value per line\n"
    "                     list     Values delimited by .separator string\n"
    "                     pretty   Pretty printed SQL results\n"
    ".nullvalue STR     Use STRING in place of NULL values\n"
    ".print STR...      Print literal STRING\n"
    ".quit              Exit this program\n"
    ".schema [TABLE]    Show the CREATE statements\n"
    ".separator STR     Change separator used by output mode and .import\n"
    ".show              Show the current values for various settings\n"
    ".tables [TABLE]    List names of tables\n"
    ".trace FILE|off    Output each SQL statement as it is run\n"
    ".width [NUM1]+     Set column widths for \"column\" mode\n";

static char zTimerHelp[] =
    ".timer ON|OFF      Turn the CPU timer measurement on or off\n";

#define DAEMON_SOCKET_LOCATION "/var/osquery/osquery.em"

/*
** These are the allowed modes.
*/
#define MODE_Line 0 /* One column per line.  Blank line between records */
#define MODE_Column 1 /* One record per line in neat columns */
#define MODE_List 2 /* One record per line with a separator */
#define MODE_Semi 3 /* Same as MODE_List but append ";" to each line */
#define MODE_Csv 4 /* Quote strings, numbers are plain */
#define MODE_Pretty 5 /* Pretty print the SQL results */

static const char *modeDescr[] = {
    "line", "column", "list", "semi", "csv", "pretty",
};

/* Make sure isatty() has a prototype.
*/
extern int isatty(int);

/* ctype macros that work with signed characters */
#define IsSpace(X) isspace((unsigned char)X)
#define IsDigit(X) isdigit((unsigned char)X)
#define ToLower(X) (char) tolower((unsigned char)X)

/* True if the timer is enabled */
static int enableTimer = 0;

/* Return the current wall-clock time */
static sqlite3_int64 timeOfDay(void) {
  static sqlite3_vfs *clockVfs = 0;
  sqlite3_int64 t;
  if (clockVfs == 0)
    clockVfs = sqlite3_vfs_find(0);
  if (clockVfs->iVersion >= 1 && clockVfs->xCurrentTimeInt64 != 0) {
    clockVfs->xCurrentTimeInt64(clockVfs, &t);
  } else {
    double r;
    clockVfs->xCurrentTime(clockVfs, &r);
    t = (sqlite3_int64)(r * 86400000.0);
  }
  return t;
}

/* Saved resource information for the beginning of an operation */
static struct rusage sBegin; /* CPU time at start */
static sqlite3_int64 iBegin; /* Wall-clock time at start */

/*
** Begin timing an operation
*/
static void beginTimer(void) {
  if (enableTimer) {
    getrusage(RUSAGE_SELF, &sBegin);
    iBegin = timeOfDay();
  }
}

/* Return the difference of two time_structs in seconds */
static double timeDiff(struct timeval *pStart, struct timeval *pEnd) {
  return (pEnd->tv_usec - pStart->tv_usec) * 0.000001 +
         (double)(pEnd->tv_sec - pStart->tv_sec);
}

/*
** Print the timing results.
*/
static void endTimer(void) {
  if (enableTimer) {
    struct rusage sEnd;
    sqlite3_int64 iEnd = timeOfDay();
    getrusage(RUSAGE_SELF, &sEnd);
    printf("Run Time: real %.3f user %f sys %f\n",
           (iEnd - iBegin) * 0.001,
           timeDiff(&sBegin.ru_utime, &sEnd.ru_utime),
           timeDiff(&sBegin.ru_stime, &sEnd.ru_stime));
  }
}

#define BEGIN_TIMER beginTimer()
#define END_TIMER endTimer()
#define HAS_TIMER 1

/*
** Used to prevent warnings about unused parameters
*/
#define UNUSED_PARAMETER(x) (void)(x)

/*
** If the following flag is set, then command execution stops
** at an error if we are not interactive.
*/
static int bail_on_error = 0;

/*
** The daemon client for sending sql statments to be executed bye
** the daemon for execution.
*/
static osquery::EXManagerClient *daemon_client = nullptr;

/*
** Threat stdin as an interactive input if the following variable
** is true.  Otherwise, assume stdin is connected to a file or pipe.
*/
static int stdin_is_interactive = 1;

/*
** True if an interrupt (Control-C) has been received.
*/
static volatile int seenInterrupt = 0;

/*
** This is the name of our program. It is set in main(), used
** in a number of other places, mostly for error messages.
*/
static char *Argv0;

/*
** Prompt strings. Initialized in main. Settable with
**   .prompt main continue
*/
static char mainPrompt[20]; /* First line prompt. default: "sqlite> "*/
static char continuePrompt[20]; /* Continuation prompt. default: "   ...> " */

/*
** A global char* and an SQL function to access its current value
** from within an SQL statement. This program used to use the
** sqlite_exec_printf() API to substitue a string into an SQL statement.
** The correct way to do this with sqlite3 is to use the bind API, but
** since the shell is built around the callback paradigm it would be a lot
** of work. Instead just use this hack, which is quite harmless.
*/
static const char *zShellStatic = 0;
static void shellstaticFunc(sqlite3_context *context,
                            int argc,
                            sqlite3_value **argv) {
  assert(0 == argc);
  assert(zShellStatic);
  UNUSED_PARAMETER(argc);
  UNUSED_PARAMETER(argv);
  sqlite3_result_text(context, zShellStatic, -1, SQLITE_STATIC);
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
static char *local_getline(char *zLine, FILE *in) {
  int nLine = ((zLine == nullptr) ? 0 : 100);
  int n = 0;

  while (1) {
    if (n + 100 > nLine) {
      nLine = nLine * 2 + 100;
      auto zLine_new = (char *)realloc(zLine, nLine);
      if (zLine_new == nullptr) {
        free(zLine);
        return nullptr;
      }
      zLine = zLine_new;
    }
    if (fgets(&zLine[n], nLine - n, in) == 0) {
      if (n == 0) {
        free(zLine);
        return nullptr;
      }
      zLine[n] = 0;
      break;
    }
    while (zLine[n]) {
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
static char *one_input_line(FILE *in, char *zPrior, int isContinuation) {
  char *zPrompt;
  char *zResult;
  if (in != 0) {
    zResult = local_getline(zPrior, in);
  } else {
    zPrompt = isContinuation ? continuePrompt : mainPrompt;
    free(zPrior);
    zResult = readline(zPrompt);
    if (zResult && *zResult)
      add_history(zResult);
  }
  return zResult;
}

struct previous_mode_data {
  int valid; /* Is there legit data in here? */
  int mode;
  int showHeader;
  int colWidth[100];
};

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
  int autoEQP; /* Run EXPLAIN QUERY PLAN prior to seach SQL statement */
  int cnt; /* Number of records displayed so far */
  FILE *out; /* Write results here */
  FILE *traceOut; /* Output for sqlite3_trace() */
  int nErr; /* Number of errors seen */
  int mode; /* An output mode setting */
  int writableSchema; /* True if PRAGMA writable_schema=ON */
  int showHeader; /* True to show column names in List or Column mode */
  char *zDestTable; /* Name of destination table when MODE_Insert */
  char separator[20]; /* Separator character for MODE_List */
  int colWidth[100]; /* Requested width of each column when in column mode*/
  int actualWidth[100]; /* Actual width of each column */
  char nullvalue[20]; /* The text to print when a NULL comes back from
                      ** the database */
  struct previous_mode_data explainPrev;
  /* Holds the mode information just before
  ** .explain ON */
  char outfile[FILENAME_MAX]; /* Filename for *out */
  const char *zDbFilename; /* name of the database file */
  char *zFreeOnClose; /* Filename to free when closing */
  const char *zVfs; /* Name of VFS to use */
  sqlite3_stmt *pStmt; /* Current statement if any. */
  FILE *pLog; /* Write log output here */
  int *aiIndent; /* Array of indents used in MODE_Explain */
  int nIndent; /* Size of array aiIndent[] */
  int iIndent; /* Index of current op in aiIndent[] */

  /* Additional attributes to be used in pretty mode */
  struct prettyprint_data *prettyPrint;
};

/*
** Number of elements in an array
*/
#define ArraySize(X) (int)(sizeof(X) / sizeof(X[0]))

/*
** Compute a string length that is limited to what can be stored in
** lower 30 bits of a 32-bit signed integer.
*/
static int strlen30(const char *z) {
  const char *z2 = z;
  while (*z2) {
    z2++;
  }
  return 0x3fffffff & (int)(z2 - z);
}

/*
** A callback for the sqlite3_log() interface.
*/
static void shellLog(void *pArg, int iErrCode, const char *zMsg) {
  struct callback_data *p = (struct callback_data *)pArg;
  if (p->pLog == 0)
    return;
  fprintf(p->pLog, "(%d) %s\n", iErrCode, zMsg);
  fflush(p->pLog);
}

/*
** Output the given string as a quoted according to C or TCL quoting rules.
*/
static void output_c_string(FILE *out, const char *z) {
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
    } else if (!isprint(c & 0xff)) {
      fprintf(out, "\\%03o", c & 0xff);
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
// clang-format off
static const char needCsvQuote[] = {
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1,
};
// clang-format on

/*
** Output a single term of CSV.  Actually, p->separator is used for
** the separator, which may or may not be a comma.  p->nullvalue is
** the null value.  Strings are quoted if necessary.
*/
static void output_csv(struct callback_data *p, const char *z, int bSep) {
  FILE *out = p->out;
  if (z == 0) {
    fprintf(out, "%s", p->nullvalue);
  } else {
    int i;
    int nSep = strlen30(p->separator);
    for (i = 0; z[i]; i++) {
      if (needCsvQuote[((unsigned char *)z)[i]] ||
          (z[i] == p->separator[0] &&
           (nSep == 1 || memcmp(z, p->separator, nSep) == 0))) {
        i = 0;
        break;
      }
    }
    if (i == 0) {
      putc('"', out);
      for (i = 0; z[i]; i++) {
        if (z[i] == '"')
          putc('"', out);
        putc(z[i], out);
      }
      putc('"', out);
    } else {
      fprintf(out, "%s", z);
    }
  }
  if (bSep) {
    fprintf(p->out, "%s", p->separator);
  }
}

#ifdef SIGINT
/*
** This routine runs when the user presses Ctrl-C
*/
static void interrupt_handler(int NotUsed) {
  UNUSED_PARAMETER(NotUsed);
  seenInterrupt = 1;
}
#endif

/*
** This is the callback routine that the shell
** invokes for each row of a query result.
*/
static int shell_callback(
    void *pArg, int nArg, char **azArg, char **azCol, int *aiType) {
  int i;
  struct callback_data *p = (struct callback_data *)pArg;

  switch (p->mode) {
  case MODE_Pretty: {
    if (p->prettyPrint->columns.size() == 0) {
      for (i = 0; i < nArg; i++) {
        p->prettyPrint->columns.push_back(std::string(azCol[i]));
      }
    }

    osquery::Row r;
    for (int i = 0; i < nArg; ++i) {
      if (azCol[i] != nullptr && azArg[i] != nullptr) {
        r[std::string(azCol[i])] = std::string(azArg[i]);
      }
    }
    osquery::computeRowLengths(r, p->prettyPrint->lengths);
    p->prettyPrint->results.push_back(r);
    break;
  }
  case MODE_Line: {
    int w = 5;
    if (azArg == 0)
      break;
    for (i = 0; i < nArg; i++) {
      int len = strlen30(azCol[i] ? azCol[i] : "");
      if (len > w)
        w = len;
    }
    if (p->cnt++ > 0)
      fprintf(p->out, "\n");
    for (i = 0; i < nArg; i++) {
      fprintf(p->out,
              "%*s = %s\n",
              w,
              azCol[i],
              azArg[i] ? azArg[i] : p->nullvalue);
    }
    break;
  }
  case MODE_Column: {
    if (p->cnt++ == 0) {
      for (i = 0; i < nArg; i++) {
        int w, n;
        if (i < ArraySize(p->colWidth)) {
          w = p->colWidth[i];
        } else {
          w = 0;
        }
        if (w == 0) {
          w = strlen30(azCol[i] ? azCol[i] : "");
          if (w < 10)
            w = 10;
          n = strlen30(azArg && azArg[i] ? azArg[i] : p->nullvalue);
          if (w < n)
            w = n;
        }
        if (i < ArraySize(p->actualWidth)) {
          p->actualWidth[i] = w;
        }
        if (p->showHeader) {
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
      if (p->showHeader) {
        for (i = 0; i < nArg; i++) {
          int w;
          if (i < ArraySize(p->actualWidth)) {
            w = p->actualWidth[i];
            if (w < 0)
              w = -w;
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
    if (azArg == 0)
      break;
    for (i = 0; i < nArg; i++) {
      int w;
      if (i < ArraySize(p->actualWidth)) {
        w = p->actualWidth[i];
      } else {
        w = 10;
      }
      if (i == 1 && p->aiIndent && p->pStmt) {
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
                azArg[i] ? azArg[i] : p->nullvalue,
                i == nArg - 1 ? "\n" : "  ");
      } else {
        fprintf(p->out,
                "%-*.*s%s",
                w,
                w,
                azArg[i] ? azArg[i] : p->nullvalue,
                i == nArg - 1 ? "\n" : "  ");
      }
    }
    break;
  }
  case MODE_Semi:
  case MODE_List: {
    if (p->cnt++ == 0 && p->showHeader) {
      for (i = 0; i < nArg; i++) {
        fprintf(p->out, "%s%s", azCol[i], i == nArg - 1 ? "\n" : p->separator);
      }
    }
    if (azArg == 0)
      break;
    for (i = 0; i < nArg; i++) {
      char *z = azArg[i];
      if (z == 0)
        z = p->nullvalue;
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
    if (p->cnt++ == 0 && p->showHeader) {
      for (i = 0; i < nArg; i++) {
        output_csv(p, azCol[i] ? azCol[i] : "", i < nArg - 1);
      }
      fprintf(p->out, "\n");
    }
    if (azArg == 0)
      break;
    for (i = 0; i < nArg; i++) {
      output_csv(p, azArg[i], i < nArg - 1);
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
static void set_table_name(struct callback_data *p, const char *zName) {
  int i, n;
  int needQuote;
  char *z;

  if (p->zDestTable) {
    free(p->zDestTable);
    p->zDestTable = 0;
  }
  if (zName == 0)
    return;
  needQuote = !isalpha((unsigned char)*zName) && *zName != '_';
  for (i = n = 0; zName[i]; i++, n++) {
    if (!isalnum((unsigned char)zName[i]) && zName[i] != '_') {
      needQuote = 1;
      if (zName[i] == '\'')
        n++;
    }
  }
  if (needQuote)
    n += 2;
  z = p->zDestTable = (char *)malloc(n + 1);
  if (z == 0) {
    fprintf(stderr, "Error: out of memory\n");
    exit(1);
  }
  n = 0;
  if (needQuote)
    z[n++] = '\'';
  for (i = 0; zName[i]; i++) {
    z[n++] = zName[i];
    if (zName[i] == '\'')
      z[n++] = '\'';
  }
  if (needQuote)
    z[n++] = '\'';
  z[n] = 0;
}

/*
** Allocate space and save off current error string.
*/
static char *save_err_msg(sqlite3 *db /* Database to query */
                          ) {
  int nErrMsg = 1 + strlen30(sqlite3_errmsg(db));
  char *zErrMsg = (char *)sqlite3_malloc(nErrMsg);
  if (zErrMsg) {
    memcpy(zErrMsg, sqlite3_errmsg(db), nErrMsg);
  }
  return zErrMsg;
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
    const char *zSql, /* SQL to be evaluated */
    int (*xCallback)(
        void *, int, char **, char **, int *), /* Callback function */
    /* (not the same as sqlite3_exec) */
    struct callback_data *pArg, /* Pointer to struct callback_data */
    char **pzErrMsg /* Error msg written here */
    ) {
  int rc = SQLITE_OK; /* Return Code */

  if (pzErrMsg) {
    *pzErrMsg = nullptr;
  }

  if (daemon_client) {
    if (pArg) {
      pArg->cnt = 0;
    }

    /* echo the sql statement if echo on */
    if (pArg && pArg->echoOn) {
      fprintf(pArg->out, "%s\n", zSql);
    }
    osquery::extensions::ExtensionResponse response;
    try {
      daemon_client->get()->query(response, std::string(zSql));
    } catch (const std::exception& e) {
      delete daemon_client;
      daemon_client = new osquery::EXManagerClient(
          std::string(DAEMON_SOCKET_LOCATION));
      rc = SQLITE_ERROR;
    }
    if (rc == SQLITE_OK && response.status.code == 0) {
      for (const auto& row : response.response) {
        int nCol = row.size();
        char *azCols[nCol]; /* Names of result columns */
        char *azVals[nCol]; /* Results */
        int aiTypes[nCol]; /* Result types */
        int i = 0;
        for (const auto &row_column : row) {
          assert(i < nCol);
          // Dropping the const qualifier.  As they are not modified anyways.
          azCols[i] = (char *)row_column.first.c_str();
          azVals[i] = (char *)row_column.second.c_str();
          aiTypes[i] = 0;  // Don't know what to set. Its unused anyways.
          i++;
        }
        if (xCallback(pArg, nCol, azVals, azCols, aiTypes)) {
          rc = SQLITE_ABORT;
          break;
        }
      }
    }
  } else {
    // Grab a lock on the managed DB instance.
    auto dbc = osquery::SQLiteDBManager::get();
    auto db = dbc.db();

    sqlite3_stmt *pStmt = nullptr; /* Statement to execute. */
    int rc2;
    const char *zLeftover; /* Tail of unprocessed SQL */

    while (zSql[0] && (SQLITE_OK == rc)) {
      rc = sqlite3_prepare_v2(db, zSql, -1, &pStmt, &zLeftover);
      if (SQLITE_OK != rc) {
        if (pzErrMsg) {
          *pzErrMsg = save_err_msg(db);
        }
      } else {
        if (!pStmt) {
          /* this happens for a comment or white-space */
          zSql = zLeftover;
          while (IsSpace(zSql[0]))
            zSql++;
          continue;
        }

        /* save off the prepared statment handle and reset row count */
        if (pArg) {
          pArg->pStmt = pStmt;
          pArg->cnt = 0;
        }

        /* echo the sql statement if echo on */
        if (pArg && pArg->echoOn) {
          const char *zStmtSql = sqlite3_sql(pStmt);
          fprintf(pArg->out, "%s\n", zStmtSql ? zStmtSql : zSql);
        }

        /* perform the first step.  this will tell us if we
        ** have a result set or not and how wide it is.
        */
        rc = sqlite3_step(pStmt);
        /* if we have a result set... */
        if (SQLITE_ROW == rc) {
          /* if we have a callback... */
          if (xCallback) {
            /* allocate space for col name ptr, value ptr, and type */
            int nCol = sqlite3_column_count(pStmt);
            void *pData = sqlite3_malloc(3 * nCol * sizeof(const char *) + 1);
            if (!pData) {
              rc = SQLITE_NOMEM;
            } else {
              char **azCols = (char **)pData; /* Names of result columns */
              char **azVals = &azCols[nCol]; /* Results */
              int *aiTypes = (int *)&azVals[nCol]; /* Result types */
              int i, x;
              assert(sizeof(int) <= sizeof(char *));
              /* save off ptrs to column names */
              for (i = 0; i < nCol; i++) {
                azCols[i] = (char *)sqlite3_column_name(pStmt, i);
              }
              do {
                /* extract the data and data types */
                for (i = 0; i < nCol; i++) {
                  aiTypes[i] = x = sqlite3_column_type(pStmt, i);
                  azVals[i] = (char *)sqlite3_column_text(pStmt, i);
                  if (!azVals[i] && (aiTypes[i] != SQLITE_NULL)) {
                    rc = SQLITE_NOMEM;
                    break; /* from for */
                  }
                } /* end for */

                /* if data and types extracted successfully... */
                if (SQLITE_ROW == rc) {
                  /* call the supplied callback with the result row data */
                  if (xCallback(pArg, nCol, azVals, azCols, aiTypes)) {
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
        if (rc != SQLITE_NOMEM)
          rc = rc2;
        if (rc == SQLITE_OK) {
          zSql = zLeftover;
          while (IsSpace(zSql[0]))
            zSql++;
        } else if (pzErrMsg) {
          *pzErrMsg = save_err_msg(db);
        }

        /* clear saved stmt handle */
        if (pArg) {
          pArg->pStmt = nullptr;
        }
      }
    } /* end while */
  }

  if (pArg && pArg->mode == MODE_Pretty) {
    if (osquery::FLAGS_json) {
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

  return rc;
}

/* Forward reference */
static int process_input(struct callback_data *p, FILE *in);

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
static void resolve_backslashes(char *z) {
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
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/*
** Interpret zArg as an integer value, possibly with suffixes.
*/
static sqlite3_int64 integerValue(const char *zArg) {
  sqlite3_int64 v = 0;
  static const struct {
    char *zSuffix;
    int iMult;
  } aMult[] = {
        {(char *)"KiB", 1024},
        {(char *)"MiB", 1024 * 1024},
        {(char *)"GiB", 1024 * 1024 * 1024},
        {(char *)"KB", 1000},
        {(char *)"MB", 1000000},
        {(char *)"GB", 1000000000},
        {(char *)"K", 1000},
        {(char *)"M", 1000000},
        {(char *)"G", 1000000000},
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
  return isNeg ? -v : v;
}

/*
** Interpret zArg as either an integer or a boolean value.  Return 1 or 0
** for TRUE and FALSE.  Return the integer value if appropriate.
*/
static int booleanValue(char *zArg) {
  int i;
  if (zArg[0] == '0' && zArg[1] == 'x') {
    for (i = 2; hexDigitValue(zArg[i]) >= 0; i++) {
    }
  } else {
    for (i = 0; zArg[i] >= '0' && zArg[i] <= '9'; i++) {
    }
  }
  if (i > 0 && zArg[i] == 0)
    return (int)(integerValue(zArg) & 0xffffffff);
  if (sqlite3_stricmp(zArg, "on") == 0 || sqlite3_stricmp(zArg, "yes") == 0) {
    return 1;
  }
  if (sqlite3_stricmp(zArg, "off") == 0 || sqlite3_stricmp(zArg, "no") == 0) {
    return 0;
  }
  fprintf(
      stderr, "ERROR: Not a boolean value: \"%s\". Assuming \"no\".\n", zArg);
  return 0;
}

/*
** Close an output file, assuming it is not stderr or stdout
*/
static void output_file_close(FILE *f) {
  if (f && f != stdout && f != stderr)
    fclose(f);
}

/*
** Try to open an output file.   The names "stdout" and "stderr" are
** recognized and do the right thing.  NULL is returned if the output
** filename is "off".
*/
static FILE *output_file_open(const char *zFile) {
  FILE *f;
  if (strcmp(zFile, "stdout") == 0) {
    f = stdout;
  } else if (strcmp(zFile, "stderr") == 0) {
    f = stderr;
  } else if (strcmp(zFile, "off") == 0) {
    f = 0;
  } else {
    f = fopen(zFile, "wb");
    if (f == 0) {
      fprintf(stderr, "Error: cannot open \"%s\"\n", zFile);
    }
  }
  return f;
}

inline void meta_tables(int nArg, char **azArg) {
  auto tables = osquery::Registry::names("table");
  std::sort(tables.begin(), tables.end());
  for (const auto &table_name : tables) {
    if (nArg == 1 || table_name.find(azArg[1]) == 0) {
      printf("  => %s\n", table_name.c_str());
    }
  }
}

inline void meta_schema(int nArg, char **azArg) {
  for (const auto &table_name : osquery::Registry::names("table")) {
    if (nArg > 1 && table_name.find(azArg[1]) != 0) {
      continue;
    }

    osquery::PluginRequest request = {{"action", "columns"}};
    osquery::PluginResponse response;

    osquery::Registry::call("table", table_name, request, response);
    std::vector<std::string> columns;
    for (const auto &column : response) {
      columns.push_back(column.at("name") + " " + column.at("type"));
    }

    printf("CREATE TABLE %s(%s);\n",
           table_name.c_str(),
           osquery::join(columns, ", ").c_str());
  }
}

/*
** If an input line begins with "." then invoke this routine to
** process that line.
**
** Return 1 on error, 2 to exit, and 0 otherwise.
*/
static int do_meta_command(char *zLine, struct callback_data *p) {
  int i = 1;
  int nArg = 0;
  int n, c;
  int rc = 0;
  char *azArg[50];

  // A meta command may act on the database, grab a lock and instance.
  auto dbc = osquery::SQLiteDBManager::get();
  auto db = dbc.db();

  /* Parse the input line into tokens.
  */
  while (zLine[i] && nArg < ArraySize(azArg)) {
    while (IsSpace(zLine[i])) {
      i++;
    }
    if (zLine[i] == 0)
      break;
    if (zLine[i] == '\'' || zLine[i] == '"') {
      int delim = zLine[i++];
      azArg[nArg++] = &zLine[i];
      while (zLine[i] && zLine[i] != delim) {
        if (zLine[i] == '\\' && delim == '"' && zLine[i + 1] != 0)
          i++;
        i++;
      }
      if (zLine[i] == delim) {
        zLine[i++] = 0;
      }
      if (delim == '"')
        resolve_backslashes(azArg[nArg - 1]);
    } else {
      azArg[nArg++] = &zLine[i];
      while (zLine[i] && !IsSpace(zLine[i])) {
        i++;
      }
      if (zLine[i])
        zLine[i++] = 0;
      resolve_backslashes(azArg[nArg - 1]);
    }
  }

  /* Process the input line.
  */
  if (nArg == 0)
    return 0; /* no tokens, no error */
  n = strlen30(azArg[0]);
  c = azArg[0][0];
  if (c == 'a' && strncmp(azArg[0], "all", n) == 0 && nArg == 2) {
    struct callback_data data;
    memcpy(&data, p, sizeof(data));
    auto query = std::string("SELECT * FROM ") + azArg[1];
    rc = shell_exec(query.c_str(), shell_callback, &data, nullptr);
    if (rc != SQLITE_OK) {
      fprintf(stderr, "Error querying table: %s\n", azArg[1]);
    }
  } else if (c == 'b' && n >= 3 && strncmp(azArg[0], "bail", n) == 0 &&
             nArg > 1 && nArg < 3) {
    bail_on_error = booleanValue(azArg[1]);
  } else if (c == 'e' && strncmp(azArg[0], "echo", n) == 0 && nArg > 1 &&
             nArg < 3) {
    p->echoOn = booleanValue(azArg[1]);
  } else if (c == 'e' && strncmp(azArg[0], "exit", n) == 0) {
    if (nArg > 1 && (rc = (int)integerValue(azArg[1])) != 0)
      exit(rc);
    rc = 2;
  } else if (c == 'h' && (strncmp(azArg[0], "header", n) == 0 ||
                          strncmp(azArg[0], "headers", n) == 0) &&
             nArg > 1 && nArg < 3) {
    p->showHeader = booleanValue(azArg[1]);
  } else if (c == 'h' && strncmp(azArg[0], "help", n) == 0) {
    fprintf(stderr, "%s", zHelp);
    if (HAS_TIMER) {
      fprintf(stderr, "%s", zTimerHelp);
    }
  } else if (c == 'l' && strncmp(azArg[0], "log", n) == 0 && nArg >= 2) {
    const char *zFile = azArg[1];
    output_file_close(p->pLog);
    p->pLog = output_file_open(zFile);
  } else if (c == 'm' && strncmp(azArg[0], "mode", n) == 0 && nArg == 2) {
    int n2 = strlen30(azArg[1]);
    if ((n2 == 4 && strncmp(azArg[1], "line", n2) == 0) ||
        (n2 == 5 && strncmp(azArg[1], "lines", n2) == 0)) {
      p->mode = MODE_Line;
    } else if ((n2 == 6 && strncmp(azArg[1], "column", n2) == 0) ||
               (n2 == 7 && strncmp(azArg[1], "columns", n2) == 0)) {
      p->mode = MODE_Column;
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
                     (int)ArraySize(p->nullvalue) - 1,
                     azArg[1]);
  } else if (c == 'p' && n >= 3 && strncmp(azArg[0], "print", n) == 0) {
    int i;
    for (i = 1; i < nArg; i++) {
      if (i > 1)
        fprintf(p->out, " ");
      fprintf(p->out, "%s", azArg[i]);
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
                     (int)sizeof(p->separator) - 1,
                     azArg[1]);
  } else if (c == 's' && strncmp(azArg[0], "show", n) == 0 && nArg == 1) {
    int i;
    fprintf(p->out, "%9.9s: %s\n", "echo", p->echoOn ? "on" : "off");
    fprintf(p->out, "%9.9s: %s\n", "headers", p->showHeader ? "on" : "off");
    fprintf(p->out, "%9.9s: %s\n", "mode", modeDescr[p->mode]);
    fprintf(p->out, "%9.9s: ", "nullvalue");
    output_c_string(p->out, p->nullvalue);
    fprintf(p->out, "\n");
    fprintf(p->out,
            "%9.9s: %s\n",
            "output",
            strlen30(p->outfile) ? p->outfile : "stdout");
    fprintf(p->out, "%9.9s: ", "separator");
    output_c_string(p->out, p->separator);
    fprintf(p->out, "\n");
    fprintf(p->out, "%9.9s: ", "width");
    for (i = 0; i < (int)ArraySize(p->colWidth) && p->colWidth[i] != 0; i++) {
      fprintf(p->out, "%d ", p->colWidth[i]);
    }
    fprintf(p->out, "\n");
  } else if (c == 't' && n > 1 && strncmp(azArg[0], "tables", n) == 0 &&
             nArg < 3) {
    meta_tables(nArg, azArg);
  } else if (c == 't' && n > 4 && strncmp(azArg[0], "timeout", n) == 0 &&
             nArg == 2) {
    sqlite3_busy_timeout(db, (int)integerValue(azArg[1]));
  } else if (HAS_TIMER && c == 't' && n >= 5 &&
             strncmp(azArg[0], "timer", n) == 0 && nArg == 2) {
    enableTimer = booleanValue(azArg[1]);
  } else if (c == 't' && strncmp(azArg[0], "trace", n) == 0 && nArg > 1) {
    output_file_close(p->traceOut);
    p->traceOut = output_file_open(azArg[1]);
  } else if (c == 'v' && strncmp(azArg[0], "version", n) == 0) {
    fprintf(p->out, "osquery %s\n", osquery::kVersion.c_str());
    fprintf(p->out, "using SQLite %s\n", sqlite3_libversion());
  } else if (c == 'w' && strncmp(azArg[0], "width", n) == 0 && nArg > 1) {
    int j;
    assert(nArg <= ArraySize(azArg));
    for (j = 1; j < nArg && j < ArraySize(p->colWidth); j++) {
      p->colWidth[j - 1] = (int)integerValue(azArg[j]);
    }
  } else if (c == 'd' && nArg == 1 &&
      strncmp(azArg[0], "daemonconnect", n) == 0) {
    if (daemon_client) {
      delete daemon_client;
    }
    daemon_client = new osquery::EXManagerClient(
        std::string(DAEMON_SOCKET_LOCATION));
  } else if (c == 'd' && nArg == 1 && strncmp(azArg[0], "disconnect", n) == 0) {
    if (daemon_client) {
      delete daemon_client;
    }
    daemon_client = nullptr;
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
static int line_contains_semicolon(const char *z, int N) {
  int i;
  if (z == nullptr) {
    return 0;
  }

  for (i = 0; i < N; i++) {
    if (z[i] == ';')
      return 1;
  }
  return 0;
}

/*
** Test to see if a line consists entirely of whitespace.
*/
static int _all_whitespace(const char *z) {
  if (z == nullptr) {
    return 0;
  }

  for (; *z; z++) {
    if (IsSpace(z[0])) {
      continue;
    }

    if (*z == '/' && z[1] == '*') {
      z += 2;
      while (*z && (*z != '*' || z[1] != '/')) {
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
      while (*z && *z != '\n') {
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
** Return TRUE if the line typed in is an SQL command terminator other
** than a semi-colon.  The SQL Server style "go" command is understood
** as is the Oracle "/".
*/
static int line_is_command_terminator(const char *zLine) {
  while (IsSpace(zLine[0])) {
    zLine++;
  };
  if (zLine[0] == '/' && _all_whitespace(&zLine[1])) {
    return 1; /* Oracle */
  }
  if (ToLower(zLine[0]) == 'g' && ToLower(zLine[1]) == 'o' &&
      _all_whitespace(&zLine[2])) {
    return 1; /* SQL Server */
  }
  return 0;
}

/*
** Return true if zSql is a complete SQL statement.  Return false if it
** ends in the middle of a string literal or C-style comment.
*/
static int line_is_complete(char *zSql, int nSql) {
  int rc;
  if (zSql == 0) {
    return 1;
  }
  zSql[nSql] = ';';
  zSql[nSql + 1] = 0;
  rc = sqlite3_complete(zSql);
  zSql[nSql] = 0;
  return rc;
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
static int process_input(struct callback_data *p, FILE *in) {
  char *zLine = 0; /* A single input line */
  char *zSql = 0; /* Accumulated SQL text */
  int nLine; /* Length of current line */
  int nSql = 0; /* Bytes of zSql[] used */
  int nAlloc = 0; /* Allocated zSql[] space */
  int nSqlPrior = 0; /* Bytes of zSql[] used by prior line */
  char *zErrMsg; /* Error message returned */
  int rc; /* Error code */
  int errCnt = 0; /* Number of errors seen */
  int lineno = 0; /* Current line number */
  int startline = 0; /* Line number for start of current input */

  while (errCnt == 0 || !bail_on_error || (in == 0 && stdin_is_interactive)) {
    fflush(p->out);
    zLine = one_input_line(in, zLine, nSql > 0);
    if (zLine == 0) {
      /* End of input */
      if (stdin_is_interactive) {
        printf("\n");
      }
      break;
    }
    if (seenInterrupt) {
      if (in != 0) {
        break;
      }
      seenInterrupt = 0;
    }
    lineno++;
    if (nSql == 0 && _all_whitespace(zLine)) {
      if (p->echoOn) {
        printf("%s\n", zLine);
      }
      continue;
    }
    if (zLine && zLine[0] == '.' && nSql == 0) {
      if (p->echoOn) {
        printf("%s\n", zLine);
      }
      rc = do_meta_command(zLine, p);
      if (rc == 2) { /* exit requested */
        break;
      } else if (rc) {
        errCnt++;
      }
      continue;
    }
    if (line_is_command_terminator(zLine) && line_is_complete(zSql, nSql)) {
      memcpy(zLine, ";", 2);
    }
    nLine = strlen30(zLine);
    if (nSql + nLine + 2 >= nAlloc) {
      nAlloc = nSql + nLine + 100;
      zSql = (char *)realloc(zSql, nAlloc);
      if (zSql == 0) {
        fprintf(stderr, "Error: out of memory\n");
        exit(1);
      }
    }
    nSqlPrior = nSql;
    if (nSql == 0) {
      int i;
      for (i = 0; zLine[i] && IsSpace(zLine[i]); i++) {
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
    if (nSql && line_contains_semicolon(&zSql[nSqlPrior], nSql - nSqlPrior) &&
        sqlite3_complete(zSql)) {
      p->cnt = 0;
      BEGIN_TIMER;
      rc = shell_exec(zSql, shell_callback, p, &zErrMsg);
      END_TIMER;
      if (rc || zErrMsg) {
        char zPrefix[100];
        if (in != 0 || !stdin_is_interactive) {
          sqlite3_snprintf(
              sizeof(zPrefix), zPrefix, "Error: near line %d:", startline);
        } else {
          sqlite3_snprintf(sizeof(zPrefix), zPrefix, "Error:");
        }
        if (zErrMsg != 0) {
          fprintf(stderr, "%s %s\n", zPrefix, zErrMsg);
          sqlite3_free(zErrMsg);
          zErrMsg = 0;
        }
        errCnt++;
      }
      nSql = 0;
    } else if (nSql && _all_whitespace(zSql)) {
      if (p->echoOn)
        printf("%s\n", zSql);
      nSql = 0;
    }
  }
  if (nSql) {
    if (!_all_whitespace(zSql)) {
      fprintf(stderr, "Error: incomplete SQL: %s\n", zSql);
    }
    free(zSql);
  }
  free(zLine);
  return errCnt > 0;
}

/*
** Initialize the state information in data
*/
static void main_init(struct callback_data *data) {
  memset(data, 0, sizeof(*data));
  data->prettyPrint = new struct prettyprint_data();
  data->mode = MODE_Pretty;
  memcpy(data->separator, "|", 2);
  data->showHeader = 1;
  sqlite3_config(SQLITE_CONFIG_URI, 1);
  sqlite3_config(SQLITE_CONFIG_LOG, shellLog, data);
  sqlite3_snprintf(sizeof(mainPrompt), mainPrompt, "osquery> ");
  sqlite3_snprintf(sizeof(continuePrompt), continuePrompt, "    ...> ");
  sqlite3_config(SQLITE_CONFIG_SINGLETHREAD);
}

/*
** Output text to the console in a font that attracts extra attention.
*/
static void printBold(const char *zText) { printf("\033[1m%s\033[0m", zText); }

namespace osquery {

int launchIntoShell(int argc, char **argv) {
  struct callback_data data;
  main_init(&data);

  {
    // Hold the manager connection instance again in callbacks.
    auto dbc = SQLiteDBManager::get();
    // Add some shell-specific functions to the instance.
    sqlite3_create_function(
        dbc.db(), "shellstatic", 0, SQLITE_UTF8, 0, shellstaticFunc, 0, 0);
  }

  Argv0 = argv[0];
  stdin_is_interactive = isatty(0);

  // SQLite: Make sure we have a valid signal handler early
  signal(SIGINT, interrupt_handler);

  int warnInmemoryDb = 1;
  data.zDbFilename = ":memory:";
  data.out = stdout;

  // Set modes and settings from CLI flags.
  if (FLAGS_list) {
    data.mode = MODE_List;
  } else if (FLAGS_line) {
    data.mode = MODE_Line;
  } else if (FLAGS_csv) {
    data.mode = MODE_Csv;
    memcpy(data.separator, ",", 2);
  } else {
    data.mode = MODE_Pretty;
  }

  sqlite3_snprintf(sizeof(data.separator), data.separator, "%s",
    FLAGS_separator.c_str());
  sqlite3_snprintf(sizeof(data.nullvalue), data.nullvalue, "%s",
    FLAGS_nullvalue.c_str());

  int rc = 0;
  if (FLAGS_L == true || FLAGS_A.size() > 0) {
    // Helper meta commands from shell switches.
    std::string query = (FLAGS_L) ? ".tables" : ".all " + FLAGS_A;
    char *cmd = new char[query.size() + 1];
    memset(cmd, 0, query.size() + 1);
    std::copy(query.begin(), query.end(), cmd);
    rc = do_meta_command(cmd, &data);
  } else if (argc > 1 && argv[1] != nullptr) {
    // Run a command or statement from CLI
    char *query = argv[1];
    char *error = 0;
    if (query[0] == '.') {
      rc = do_meta_command(query, &data);
      rc = (rc == 2) ? 0 : rc;
    } else {
      rc = shell_exec(query, shell_callback, &data, &error);
      if (error != 0) {
        fprintf(stderr, "Error: %s\n", error);
        return (rc != 0) ? rc : 1;
      } else if (rc != 0) {
        fprintf(stderr, "Error: unable to process SQL \"%s\"\n", query);
        return rc;
      }
    }
  } else {
    // Run commands received from standard input
    if (stdin_is_interactive) {
      printBold("osquery");
      printf(
          " - being built, with love, at Facebook\n"
          "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
      if (warnInmemoryDb) {
        printf("Using a ");
        printBold("virtual database");
        printf(". Need help, type '.help'\n");
      }

      auto history_file = osquery::osqueryHomeDirectory() + "/.history";
      read_history(history_file.c_str());
      rc = process_input(&data, 0);
      stifle_history(100);
      write_history(history_file.c_str());
    } else {
      rc = process_input(&data, stdin);
    }
  }

  set_table_name(&data, 0);
  sqlite3_free(data.zFreeOnClose);

  if (daemon_client) {
    delete daemon_client;
    daemon_client = nullptr;
  }

  if (data.prettyPrint != nullptr) {
    delete data.prettyPrint;
  }
  return rc;
}
}
