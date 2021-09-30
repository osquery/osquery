
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.4.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 1

/* Substitute the variable and function names.  */
#define yyparse         augl_parse
#define yylex           augl_lex
#define yyerror         augl_error
#define yylval          augl_lval
#define yychar          augl_char
#define yydebug         augl_debug
#define yynerrs         augl_nerrs
#define yylloc          augl_lloc

/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 1 "parser.y"


#include <config.h>

#include "internal.h"
#include "syntax.h"
#include "list.h"
#include "errcode.h"
#include <stdio.h>

/* Work around a problem on FreeBSD where Bison looks for _STDLIB_H
 * to see if stdlib.h has been included, but the system includes
 * use _STDLIB_H_
 */
#if HAVE_STDLIB_H && ! defined _STDLIB_H
#  include <stdlib.h>
#  define _STDLIB_H 1
#endif

#define YYDEBUG 1

int augl_parse_file(struct augeas *aug, const char *name, struct term **term);

typedef void *yyscan_t;
typedef struct info YYLTYPE;
#define YYLTYPE_IS_DECLARED 1
/* The lack of reference counting on filename is intentional */
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
  do {                                                                  \
    (Current).filename = augl_get_info(scanner)->filename;              \
    (Current).error = augl_get_info(scanner)->error;                    \
    if (N) {                                                            \
        (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;          \
        (Current).first_column = YYRHSLOC (Rhs, 1).first_column;        \
        (Current).last_line    = YYRHSLOC (Rhs, N).last_line;           \
        (Current).last_column  = YYRHSLOC (Rhs, N).last_column;         \
    } else {                                                            \
      (Current).first_line   = (Current).last_line   =                  \
	    YYRHSLOC (Rhs, 0).last_line;                                    \
	  (Current).first_column = (Current).last_column =                  \
	    YYRHSLOC (Rhs, 0).last_column;                                  \
    }                                                                   \
  } while (0)


/* Line 189 of yacc.c  */
#line 127 "parser.c"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     DQUOTED = 258,
     REGEXP = 259,
     LIDENT = 260,
     UIDENT = 261,
     QIDENT = 262,
     ARROW = 263,
     KW_MODULE = 264,
     KW_AUTOLOAD = 265,
     KW_LET = 266,
     KW_LET_REC = 267,
     KW_IN = 268,
     KW_STRING = 269,
     KW_REGEXP = 270,
     KW_LENS = 271,
     KW_TEST = 272,
     KW_GET = 273,
     KW_PUT = 274,
     KW_AFTER = 275
   };
#endif
/* Tokens.  */
#define DQUOTED 258
#define REGEXP 259
#define LIDENT 260
#define UIDENT 261
#define QIDENT 262
#define ARROW 263
#define KW_MODULE 264
#define KW_AUTOLOAD 265
#define KW_LET 266
#define KW_LET_REC 267
#define KW_IN 268
#define KW_STRING 269
#define KW_REGEXP 270
#define KW_LENS 271
#define KW_TEST 272
#define KW_GET 273
#define KW_PUT 274
#define KW_AFTER 275




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 89 "parser.y"

  struct term    *term;
  struct type    *type;
  struct ident   *ident;
  struct tree    *tree;
  char           *string;
  struct {
    int             nocase;
    char           *pattern;
  } regexp;
  int            intval;
  enum quant_tag quant;



/* Line 214 of yacc.c  */
#line 219 "parser.c"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
} YYLTYPE;
# define yyltype YYLTYPE /* obsolescent; will be withdrawn */
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif

/* "%code provides" blocks.  */

/* Line 261 of yacc.c  */
#line 46 "parser.y"

#include "info.h"

/* Track custom scanner state */
struct state {
  struct info *info;
  unsigned int comment_depth;
};




/* Line 261 of yacc.c  */
#line 256 "parser.c"

/* Copy the second part of user declarations.  */

/* Line 264 of yacc.c  */
#line 114 "parser.y"

/* Lexer */
extern int augl_lex (YYSTYPE * yylval_param,struct info * yylloc_param ,yyscan_t yyscanner);
int augl_init_lexer(struct state *state, yyscan_t * scanner);
void augl_close_lexer(yyscan_t *scanner);
int augl_lex_destroy (yyscan_t yyscanner );
int augl_get_lineno (yyscan_t yyscanner );
int augl_get_column  (yyscan_t yyscanner);
struct info *augl_get_info(yyscan_t yyscanner);
char *augl_get_text (yyscan_t yyscanner );

static void augl_error(struct info *locp, struct term **term,
                       yyscan_t scanner, const char *s);

/* TERM construction */
 static struct info *clone_info(struct info *locp);
 static struct term *make_module(char *ident, char *autoload,
                                 struct term *decls,
                                 struct info *locp);

 static struct term *make_bind(char *ident, struct term *params,
                             struct term *exp, struct term *decls,
                             struct info *locp);
 static struct term *make_bind_rec(char *ident, struct term *exp,
                                   struct term *decls, struct info *locp);
 static struct term *make_let(char *ident, struct term *params,
                              struct term *exp, struct term *body,
                              struct info *locp);
 static struct term *make_binop(enum term_tag tag,
                               struct term *left, struct term *right,
                               struct info *locp);
 static struct term *make_unop(enum term_tag tag,
                              struct term *exp, struct info *locp);
 static struct term *make_ident(char *qname, struct info *locp);
 static struct term *make_unit_term(struct info *locp);
 static struct term *make_string_term(char *value, struct info *locp);
 static struct term *make_regexp_term(char *pattern,
                                      int nocase, struct info *locp);
 static struct term *make_rep(struct term *exp, enum quant_tag quant,
                             struct info *locp);

 static struct term *make_get_test(struct term *lens, struct term *arg,
                                   struct info *info);
 static struct term *make_put_test(struct term *lens, struct term *arg,
                                   struct term *cmds, struct info *info);
 static struct term *make_test(struct term *test, struct term *result,
                               enum test_result_tag tr_tag,
                               struct term *decls, struct info *locp);
 static struct term *make_tree_value(struct tree *, struct info*);
 static struct tree *tree_concat(struct tree *, struct tree *);

#define LOC_MERGE(a, b, c)                                              \
 do {                                                                   \
   (a).filename     = (b).filename;                                     \
   (a).first_line   = (b).first_line;                                   \
   (a).first_column = (b).first_column;                                 \
   (a).last_line    = (c).last_line;                                    \
   (a).last_column  = (c).last_column;                                  \
   (a).error        = (b).error;                                        \
 } while(0);



/* Line 264 of yacc.c  */
#line 326 "parser.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
	     && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  4
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   129

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  36
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  25
/* YYNRULES -- Number of rules.  */
#define YYNRULES  61
/* YYNRULES -- Number of states.  */
#define YYNSTATES  113

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   275

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      28,    29,    23,    32,     2,    26,    27,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    33,    24,
       2,    21,     2,    22,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    30,     2,    31,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    34,    25,    35,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
       0,     0,     3,     9,    12,    13,    20,    26,    32,    38,
      39,    43,    49,    51,    53,    61,    63,    67,    69,    73,
      75,    77,    81,    83,    87,    89,    92,    94,    96,    98,
     100,   104,   108,   111,   114,   116,   118,   120,   122,   124,
     126,   128,   130,   133,   134,   140,   142,   144,   146,   150,
     152,   154,   156,   158,   162,   167,   171,   176,   177,   180,
     185,   187
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
      37,     0,    -1,     9,     6,    21,    38,    39,    -1,    10,
       5,    -1,    -1,    11,     5,    52,    21,    42,    39,    -1,
      12,     5,    21,    42,    39,    -1,    17,    40,    21,    42,
      39,    -1,    17,    40,    21,    41,    39,    -1,    -1,    48,
      18,    42,    -1,    48,    19,    48,    20,    42,    -1,    22,
      -1,    23,    -1,    11,     5,    52,    21,    42,    13,    42,
      -1,    43,    -1,    43,    24,    44,    -1,    44,    -1,    44,
      25,    45,    -1,    45,    -1,    57,    -1,    45,    26,    46,
      -1,    46,    -1,    46,    27,    47,    -1,    47,    -1,    47,
      49,    -1,    49,    -1,    51,    -1,     3,    -1,     4,    -1,
      28,    42,    29,    -1,    30,    42,    31,    -1,    28,    29,
      -1,    48,    50,    -1,    48,    -1,    23,    -1,    32,    -1,
      22,    -1,     5,    -1,     7,    -1,    18,    -1,    19,    -1,
      53,    52,    -1,    -1,    28,    54,    33,    55,    29,    -1,
       5,    -1,    18,    -1,    19,    -1,    56,     8,    55,    -1,
      56,    -1,    14,    -1,    15,    -1,    16,    -1,    28,    55,
      29,    -1,    57,    34,    59,    35,    -1,    34,    59,    35,
      -1,    58,    34,    59,    35,    -1,    -1,    60,    58,    -1,
      60,    21,     3,    58,    -1,     3,    -1,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   179,   179,   182,   185,   187,   192,   197,   202,   208,
     212,   214,   217,   219,   223,   228,   230,   232,   235,   237,
     239,   242,   244,   247,   249,   252,   254,   257,   259,   261,
     263,   265,   267,   270,   272,   275,   277,   279,   282,   284,
     286,   288,   291,   294,   296,   299,   301,   303,   306,   308,
     311,   313,   315,   317,   320,   322,   325,   330,   332,   336,
     340,   342
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "DQUOTED", "REGEXP", "LIDENT", "UIDENT",
  "QIDENT", "ARROW", "KW_MODULE", "KW_AUTOLOAD", "KW_LET", "KW_LET_REC",
  "KW_IN", "KW_STRING", "KW_REGEXP", "KW_LENS", "KW_TEST", "KW_GET",
  "KW_PUT", "KW_AFTER", "'='", "'?'", "'*'", "';'", "'|'", "'-'", "'.'",
  "'('", "')'", "'['", "']'", "'+'", "':'", "'{'", "'}'", "$accept",
  "start", "autoload", "decls", "test_exp", "test_special_res", "exp",
  "composeexp", "unionexp", "minusexp", "catexp", "appexp", "aexp", "rexp",
  "rep", "qid", "param_list", "param", "id", "type", "atype", "tree_const",
  "tree_const2", "tree_branch", "tree_label", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,    61,    63,    42,    59,   124,    45,    46,    40,    41,
      91,    93,    43,    58,   123,   125
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    36,    37,    38,    38,    39,    39,    39,    39,    39,
      40,    40,    41,    41,    42,    42,    43,    43,    44,    44,
      44,    45,    45,    46,    46,    47,    47,    48,    48,    48,
      48,    48,    48,    49,    49,    50,    50,    50,    51,    51,
      51,    51,    52,    52,    53,    54,    54,    54,    55,    55,
      56,    56,    56,    56,    57,    57,    58,    58,    59,    59,
      60,    60
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     5,     2,     0,     6,     5,     5,     5,     0,
       3,     5,     1,     1,     7,     1,     3,     1,     3,     1,
       1,     3,     1,     3,     1,     2,     1,     1,     1,     1,
       3,     3,     2,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     0,     5,     1,     1,     1,     3,     1,
       1,     1,     1,     3,     4,     3,     4,     0,     2,     4,
       1,     0
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       0,     0,     0,     0,     1,     4,     0,     9,     3,     0,
       0,     0,     2,    43,     0,    28,    29,    38,    39,    40,
      41,     0,     0,     0,     0,    27,     0,     0,    43,     0,
       0,    32,    61,     0,    15,    17,    19,    22,    24,    34,
      26,    20,     0,     0,     0,     0,    45,    46,    47,     0,
       0,    42,     9,    43,    60,     0,    57,    30,     0,     0,
       0,     0,    25,    37,    35,    36,    33,    61,    31,    12,
      13,     9,     9,    10,     0,     0,     9,     6,     0,    55,
       0,    58,    16,    18,    21,    23,     0,     8,     7,     0,
      50,    51,    52,     0,     0,    49,     5,     0,    57,    61,
      54,    11,     0,    44,     0,     0,    59,     0,    53,    48,
       0,    56,    14
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     2,     7,    12,    23,    71,    33,    34,    35,    36,
      37,    38,    39,    40,    66,    25,    27,    28,    49,    94,
      95,    41,    81,    55,    56
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -90
static const yytype_int8 yypact[] =
{
      -1,     8,    16,    -4,   -90,    14,    26,    53,   -90,    27,
      29,    92,   -90,    11,    25,   -90,   -90,   -90,   -90,   -90,
     -90,    50,    55,    28,    -6,   -90,     1,    30,    11,    55,
      38,   -90,    44,    34,    52,    57,    51,    59,    92,    49,
     -90,    64,    56,    22,    55,    92,   -90,   -90,   -90,    60,
      55,   -90,    53,    11,   -90,    65,    80,   -90,    87,    92,
      92,    92,   -90,   -90,   -90,   -90,   -90,    44,   -90,   -90,
     -90,    53,    53,   -90,    82,    -5,    53,   -90,    83,   -90,
     100,    73,    57,    51,    59,    92,    74,   -90,   -90,    55,
     -90,   -90,   -90,    -5,    79,   104,   -90,    55,   -90,    44,
     -90,   -90,    84,   -90,    -5,   101,    73,    81,   -90,   -90,
      55,   -90,   -90
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -90,   -90,   -90,   -34,   -90,   -90,   -22,   -90,    61,    66,
      58,    62,    -9,   -37,   -90,   -90,   -23,   -90,   -90,   -89,
     -90,   -90,    31,   -64,   -90
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
      42,    62,    24,    86,   102,    51,    46,    52,     1,    90,
      91,    92,    44,    45,     3,   109,     4,     5,    77,    47,
      48,    72,    73,    93,     6,    15,    16,    17,    76,    18,
      78,     8,    13,    30,    14,   107,    74,    87,    88,    26,
      19,    20,    96,    53,    69,    70,    29,    54,    62,    43,
      21,    50,    22,    15,    16,    17,    32,    18,    15,    16,
      17,    30,    18,    57,     9,    10,    30,   101,    19,    20,
      11,    63,    64,    19,    20,   105,    58,    60,    21,    31,
      22,    65,    59,    21,    32,    22,    61,    68,   112,    32,
      15,    16,    17,    75,    18,    15,    16,    17,    67,    18,
      79,    80,    89,    98,    97,    19,    20,    99,   103,   100,
      19,    20,   104,   108,   110,    21,   111,    22,    84,    82,
      21,    32,    22,    85,     0,    83,     0,     0,     0,   106
};

static const yytype_int8 yycheck[] =
{
      22,    38,    11,    67,    93,    28,     5,    29,     9,    14,
      15,    16,    18,    19,     6,   104,     0,    21,    52,    18,
      19,    43,    44,    28,    10,     3,     4,     5,    50,     7,
      53,     5,     5,    11,     5,    99,    45,    71,    72,    28,
      18,    19,    76,     5,    22,    23,    21,     3,    85,    21,
      28,    21,    30,     3,     4,     5,    34,     7,     3,     4,
       5,    11,     7,    29,    11,    12,    11,    89,    18,    19,
      17,    22,    23,    18,    19,    97,    24,    26,    28,    29,
      30,    32,    25,    28,    34,    30,    27,    31,   110,    34,
       3,     4,     5,    33,     7,     3,     4,     5,    34,     7,
      35,    21,    20,     3,    21,    18,    19,    34,    29,    35,
      18,    19,     8,    29,    13,    28,    35,    30,    60,    58,
      28,    34,    30,    61,    -1,    59,    -1,    -1,    -1,    98
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,     9,    37,     6,     0,    21,    10,    38,     5,    11,
      12,    17,    39,     5,     5,     3,     4,     5,     7,    18,
      19,    28,    30,    40,    48,    51,    28,    52,    53,    21,
      11,    29,    34,    42,    43,    44,    45,    46,    47,    48,
      49,    57,    42,    21,    18,    19,     5,    18,    19,    54,
      21,    52,    42,     5,     3,    59,    60,    29,    24,    25,
      26,    27,    49,    22,    23,    32,    50,    34,    31,    22,
      23,    41,    42,    42,    48,    33,    42,    39,    52,    35,
      21,    58,    44,    45,    46,    47,    59,    39,    39,    20,
      14,    15,    16,    28,    55,    56,    39,    21,     3,    34,
      35,    42,    55,    29,     8,    42,    58,    59,    29,    55,
      13,    35,    42
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (&yylloc, term, scanner, YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, &yylloc, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval, &yylloc, scanner)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value, Location, term, scanner); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, term, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
    struct term **term;
    yyscan_t scanner;
#endif
{
  if (!yyvaluep)
    return;
  YYUSE (yylocationp);
  YYUSE (term);
  YYUSE (scanner);
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep, yylocationp, term, scanner)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
    YYLTYPE const * const yylocationp;
    struct term **term;
    yyscan_t scanner;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, term, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule, struct term **term, yyscan_t scanner)
#else
static void
yy_reduce_print (yyvsp, yylsp, yyrule, term, scanner)
    YYSTYPE *yyvsp;
    YYLTYPE *yylsp;
    int yyrule;
    struct term **term;
    yyscan_t scanner;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       , &(yylsp[(yyi + 1) - (yynrhs)])		       , term, scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, yylsp, Rule, term, scanner); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct term **term, yyscan_t scanner)
#else
static void
yydestruct (yymsg, yytype, yyvaluep, yylocationp, term, scanner)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
    YYLTYPE *yylocationp;
    struct term **term;
    yyscan_t scanner;
#endif
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  YYUSE (term);
  YYUSE (scanner);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (struct term **term, yyscan_t scanner);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */





/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (struct term **term, yyscan_t scanner)
#else
int
yyparse (term, scanner)
    struct term **term;
    yyscan_t scanner;
#endif
#endif
{
/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

/* Location data for the lookahead symbol.  */
YYLTYPE yylloc;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.
       `yyls': related to locations.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    /* The location stack.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls;
    YYLTYPE *yylsp;

    /* The locations where the error started and ended.  */
    YYLTYPE yyerror_range[2];

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yyls = yylsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;
  yylsp = yyls;

#if YYLTYPE_IS_TRIVIAL
  /* Initialize the default location before parsing starts.  */
  yylloc.first_line   = yylloc.last_line   = 1;
  yylloc.first_column = yylloc.last_column = 1;
#endif

/* User initialization code.  */

/* Line 1242 of yacc.c  */
#line 66 "parser.y"
{
  yylloc.first_line   = 1;
  yylloc.first_column = 0;
  yylloc.last_line    = 1;
  yylloc.last_column  = 0;
  yylloc.filename     = augl_get_info(scanner)->filename;
  yylloc.error        = augl_get_info(scanner)->error;
}

/* Line 1242 of yacc.c  */
#line 1496 "parser.c"
  yylsp[0] = yylloc;

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;
	YYLTYPE *yyls1 = yyls;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);

	yyls = yyls1;
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
	YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:

/* Line 1455 of yacc.c  */
#line 180 "parser.y"
    { (*term) = make_module((yyvsp[(2) - (5)].string), (yyvsp[(4) - (5)].string), (yyvsp[(5) - (5)].term), &(yylsp[(1) - (5)])); }
    break;

  case 3:

/* Line 1455 of yacc.c  */
#line 183 "parser.y"
    { (yyval.string) = (yyvsp[(2) - (2)].string); }
    break;

  case 4:

/* Line 1455 of yacc.c  */
#line 185 "parser.y"
    { (yyval.string) = NULL; }
    break;

  case 5:

/* Line 1455 of yacc.c  */
#line 188 "parser.y"
    {
         LOC_MERGE((yylsp[(1) - (6)]), (yylsp[(1) - (6)]), (yylsp[(5) - (6)]));
         (yyval.term) = make_bind((yyvsp[(2) - (6)].string), (yyvsp[(3) - (6)].term), (yyvsp[(5) - (6)].term), (yyvsp[(6) - (6)].term), &(yylsp[(1) - (6)]));
       }
    break;

  case 6:

/* Line 1455 of yacc.c  */
#line 193 "parser.y"
    {
         LOC_MERGE((yylsp[(1) - (5)]), (yylsp[(1) - (5)]), (yylsp[(4) - (5)]));
         (yyval.term) = make_bind_rec((yyvsp[(2) - (5)].string), (yyvsp[(4) - (5)].term), (yyvsp[(5) - (5)].term), &(yylsp[(1) - (5)]));
       }
    break;

  case 7:

/* Line 1455 of yacc.c  */
#line 198 "parser.y"
    {
         LOC_MERGE((yylsp[(1) - (5)]), (yylsp[(1) - (5)]), (yylsp[(4) - (5)]));
         (yyval.term) = make_test((yyvsp[(2) - (5)].term), (yyvsp[(4) - (5)].term), TR_CHECK, (yyvsp[(5) - (5)].term), &(yylsp[(1) - (5)]));
       }
    break;

  case 8:

/* Line 1455 of yacc.c  */
#line 203 "parser.y"
    {
         LOC_MERGE((yylsp[(1) - (5)]), (yylsp[(1) - (5)]), (yylsp[(4) - (5)]));
         (yyval.term) = make_test((yyvsp[(2) - (5)].term), NULL, (yyvsp[(4) - (5)].intval), (yyvsp[(5) - (5)].term), &(yylsp[(1) - (5)]));
       }
    break;

  case 9:

/* Line 1455 of yacc.c  */
#line 208 "parser.y"
    { (yyval.term) = NULL; }
    break;

  case 10:

/* Line 1455 of yacc.c  */
#line 213 "parser.y"
    { (yyval.term) = make_get_test((yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), &(yyloc)); }
    break;

  case 11:

/* Line 1455 of yacc.c  */
#line 215 "parser.y"
    { (yyval.term) = make_put_test((yyvsp[(1) - (5)].term), (yyvsp[(3) - (5)].term), (yyvsp[(5) - (5)].term), &(yyloc)); }
    break;

  case 12:

/* Line 1455 of yacc.c  */
#line 218 "parser.y"
    { (yyval.intval) = TR_PRINT; }
    break;

  case 13:

/* Line 1455 of yacc.c  */
#line 220 "parser.y"
    { (yyval.intval) = TR_EXN; }
    break;

  case 14:

/* Line 1455 of yacc.c  */
#line 224 "parser.y"
    {
       LOC_MERGE((yylsp[(1) - (7)]), (yylsp[(1) - (7)]), (yylsp[(6) - (7)]));
       (yyval.term) = make_let((yyvsp[(2) - (7)].string), (yyvsp[(3) - (7)].term), (yyvsp[(5) - (7)].term), (yyvsp[(7) - (7)].term), &(yylsp[(1) - (7)]));
     }
    break;

  case 16:

/* Line 1455 of yacc.c  */
#line 231 "parser.y"
    { (yyval.term) = make_binop(A_COMPOSE, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), &(yyloc)); }
    break;

  case 17:

/* Line 1455 of yacc.c  */
#line 233 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 18:

/* Line 1455 of yacc.c  */
#line 236 "parser.y"
    { (yyval.term) = make_binop(A_UNION, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), &(yyloc)); }
    break;

  case 19:

/* Line 1455 of yacc.c  */
#line 238 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 20:

/* Line 1455 of yacc.c  */
#line 240 "parser.y"
    { (yyval.term) = make_tree_value((yyvsp[(1) - (1)].tree), &(yylsp[(1) - (1)])); }
    break;

  case 21:

/* Line 1455 of yacc.c  */
#line 243 "parser.y"
    { (yyval.term) = make_binop(A_MINUS, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), &(yyloc)); }
    break;

  case 22:

/* Line 1455 of yacc.c  */
#line 245 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 23:

/* Line 1455 of yacc.c  */
#line 248 "parser.y"
    { (yyval.term) = make_binop(A_CONCAT, (yyvsp[(1) - (3)].term), (yyvsp[(3) - (3)].term), &(yyloc)); }
    break;

  case 24:

/* Line 1455 of yacc.c  */
#line 250 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 25:

/* Line 1455 of yacc.c  */
#line 253 "parser.y"
    { (yyval.term) = make_binop(A_APP, (yyvsp[(1) - (2)].term), (yyvsp[(2) - (2)].term), &(yyloc)); }
    break;

  case 26:

/* Line 1455 of yacc.c  */
#line 255 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 27:

/* Line 1455 of yacc.c  */
#line 258 "parser.y"
    { (yyval.term) = make_ident((yyvsp[(1) - (1)].string), &(yylsp[(1) - (1)])); }
    break;

  case 28:

/* Line 1455 of yacc.c  */
#line 260 "parser.y"
    { (yyval.term) = make_string_term((yyvsp[(1) - (1)].string), &(yylsp[(1) - (1)])); }
    break;

  case 29:

/* Line 1455 of yacc.c  */
#line 262 "parser.y"
    { (yyval.term) = make_regexp_term((yyvsp[(1) - (1)].regexp).pattern, (yyvsp[(1) - (1)].regexp).nocase, &(yylsp[(1) - (1)])); }
    break;

  case 30:

/* Line 1455 of yacc.c  */
#line 264 "parser.y"
    { (yyval.term) = (yyvsp[(2) - (3)].term); }
    break;

  case 31:

/* Line 1455 of yacc.c  */
#line 266 "parser.y"
    { (yyval.term) = make_unop(A_BRACKET, (yyvsp[(2) - (3)].term), &(yyloc)); }
    break;

  case 32:

/* Line 1455 of yacc.c  */
#line 268 "parser.y"
    { (yyval.term) = make_unit_term(&(yyloc)); }
    break;

  case 33:

/* Line 1455 of yacc.c  */
#line 271 "parser.y"
    { (yyval.term) = make_rep((yyvsp[(1) - (2)].term), (yyvsp[(2) - (2)].quant), &(yyloc)); }
    break;

  case 34:

/* Line 1455 of yacc.c  */
#line 273 "parser.y"
    { (yyval.term) = (yyvsp[(1) - (1)].term); }
    break;

  case 35:

/* Line 1455 of yacc.c  */
#line 276 "parser.y"
    { (yyval.quant) = Q_STAR; }
    break;

  case 36:

/* Line 1455 of yacc.c  */
#line 278 "parser.y"
    { (yyval.quant) = Q_PLUS; }
    break;

  case 37:

/* Line 1455 of yacc.c  */
#line 280 "parser.y"
    { (yyval.quant) = Q_MAYBE; }
    break;

  case 38:

/* Line 1455 of yacc.c  */
#line 283 "parser.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 39:

/* Line 1455 of yacc.c  */
#line 285 "parser.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 40:

/* Line 1455 of yacc.c  */
#line 287 "parser.y"
    { (yyval.string) = strdup("get"); }
    break;

  case 41:

/* Line 1455 of yacc.c  */
#line 289 "parser.y"
    { (yyval.string) = strdup("put"); }
    break;

  case 42:

/* Line 1455 of yacc.c  */
#line 292 "parser.y"
    { (yyval.term) = (yyvsp[(2) - (2)].term); list_cons((yyval.term), (yyvsp[(1) - (2)].term)); }
    break;

  case 43:

/* Line 1455 of yacc.c  */
#line 294 "parser.y"
    { (yyval.term) = NULL; }
    break;

  case 44:

/* Line 1455 of yacc.c  */
#line 297 "parser.y"
    { (yyval.term) = make_param((yyvsp[(2) - (5)].string), (yyvsp[(4) - (5)].type), clone_info(&(yylsp[(1) - (5)]))); }
    break;

  case 45:

/* Line 1455 of yacc.c  */
#line 300 "parser.y"
    { (yyval.string) = (yyvsp[(1) - (1)].string); }
    break;

  case 46:

/* Line 1455 of yacc.c  */
#line 302 "parser.y"
    { (yyval.string) = strdup("get"); }
    break;

  case 47:

/* Line 1455 of yacc.c  */
#line 304 "parser.y"
    { (yyval.string) = strdup("put"); }
    break;

  case 48:

/* Line 1455 of yacc.c  */
#line 307 "parser.y"
    { (yyval.type) = make_arrow_type((yyvsp[(1) - (3)].type), (yyvsp[(3) - (3)].type)); }
    break;

  case 49:

/* Line 1455 of yacc.c  */
#line 309 "parser.y"
    { (yyval.type) = (yyvsp[(1) - (1)].type); }
    break;

  case 50:

/* Line 1455 of yacc.c  */
#line 312 "parser.y"
    { (yyval.type) = make_base_type(T_STRING); }
    break;

  case 51:

/* Line 1455 of yacc.c  */
#line 314 "parser.y"
    { (yyval.type) = make_base_type(T_REGEXP); }
    break;

  case 52:

/* Line 1455 of yacc.c  */
#line 316 "parser.y"
    { (yyval.type) = make_base_type(T_LENS); }
    break;

  case 53:

/* Line 1455 of yacc.c  */
#line 318 "parser.y"
    { (yyval.type) = (yyvsp[(2) - (3)].type); }
    break;

  case 54:

/* Line 1455 of yacc.c  */
#line 321 "parser.y"
    { (yyval.tree) = tree_concat((yyvsp[(1) - (4)].tree), (yyvsp[(3) - (4)].tree)); }
    break;

  case 55:

/* Line 1455 of yacc.c  */
#line 323 "parser.y"
    { (yyval.tree) = tree_concat((yyvsp[(2) - (3)].tree), NULL); }
    break;

  case 56:

/* Line 1455 of yacc.c  */
#line 326 "parser.y"
    {
              (yyval.tree) = tree_concat((yyvsp[(1) - (4)].tree), (yyvsp[(3) - (4)].tree));
            }
    break;

  case 57:

/* Line 1455 of yacc.c  */
#line 330 "parser.y"
    { (yyval.tree) = NULL; }
    break;

  case 58:

/* Line 1455 of yacc.c  */
#line 333 "parser.y"
    {
               (yyval.tree) = make_tree((yyvsp[(1) - (2)].string), NULL, NULL, (yyvsp[(2) - (2)].tree));
             }
    break;

  case 59:

/* Line 1455 of yacc.c  */
#line 337 "parser.y"
    {
               (yyval.tree) = make_tree((yyvsp[(1) - (4)].string), (yyvsp[(3) - (4)].string), NULL, (yyvsp[(4) - (4)].tree));
             }
    break;

  case 61:

/* Line 1455 of yacc.c  */
#line 342 "parser.y"
    { (yyval.string) = NULL; }
    break;



/* Line 1455 of yacc.c  */
#line 2111 "parser.c"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (&yylloc, term, scanner, YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (&yylloc, term, scanner, yymsg);
	  }
	else
	  {
	    yyerror (&yylloc, term, scanner, YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }

  yyerror_range[0] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval, &yylloc, term, scanner);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[0] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;

      yyerror_range[0] = *yylsp;
      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp, yylsp, term, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;

  yyerror_range[1] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the lookahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, (yyerror_range - 1), 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, term, scanner, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval, &yylloc, term, scanner);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp, yylsp, term, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



/* Line 1675 of yacc.c  */
#line 343 "parser.y"


int augl_parse_file(struct augeas *aug, const char *name,
                    struct term **term) {
  yyscan_t          scanner;
  struct state      state;
  struct string  *sname = NULL;
  struct info    info;
  int result = -1;
  int r;

  *term = NULL;

  r = make_ref(sname);
  ERR_NOMEM(r < 0, aug);

  sname->str = strdup(name);
  ERR_NOMEM(sname->str == NULL, aug);

  MEMZERO(&info, 1);
  info.ref = UINT_MAX;
  info.filename = sname;
  info.error = aug->error;

  MEMZERO(&state, 1);
  state.info = &info;
  state.comment_depth = 0;

  if (augl_init_lexer(&state, &scanner) < 0) {
    augl_error(&info, term, NULL, "file not found");
    goto error;
  }

  yydebug = getenv("YYDEBUG") != NULL;
  r = augl_parse(term, scanner);
  augl_close_lexer(scanner);
  augl_lex_destroy(scanner);
  if (r == 1) {
    augl_error(&info, term, NULL, "syntax error");
    goto error;
  } else if (r == 2) {
    augl_error(&info, term, NULL, "parser ran out of memory");
    ERR_NOMEM(1, aug);
  }
  result = 0;

 error:
  unref(sname, string);
  // free TERM
  return result;
}

// FIXME: Nothing here checks for alloc errors.
static struct info *clone_info(struct info *locp) {
  struct info *info;
  make_ref(info);
  info->filename     = ref(locp->filename);
  info->first_line   = locp->first_line;
  info->first_column = locp->first_column;
  info->last_line    = locp->last_line;
  info->last_column  = locp->last_column;
  info->error        = locp->error;
  return info;
}

static struct term *make_term_locp(enum term_tag tag, struct info *locp) {
  struct info *info = clone_info(locp);
  return make_term(tag, info);
}

static struct term *make_module(char *ident, char *autoload,
                                struct term *decls,
                                struct info *locp) {
  struct term *term = make_term_locp(A_MODULE, locp);
  term->mname = ident;
  term->autoload = autoload;
  term->decls = decls;
  return term;
}

static struct term *make_bind(char *ident, struct term *params,
                              struct term *exp, struct term *decls,
                              struct info *locp) {
  struct term *term = make_term_locp(A_BIND, locp);
  if (params != NULL)
    exp = build_func(params, exp);

  term->bname = ident;
  term->exp = exp;
  list_cons(decls, term);
  return decls;
}

static struct term *make_bind_rec(char *ident, struct term *exp,
                                  struct term *decls, struct info *locp) {
  /* Desugar let rec IDENT = EXP as
   *  let IDENT =
   *    let RLENS = (lns_make_rec) in
   *    lns_check_rec ((lambda IDENT: EXP) RLENS) RLENS
   * where RLENS is a brandnew recursive lens.
   *
   * That only works since we know that 'let rec' is only defined for lenses,
   * not general purposes functions, i.e. we know that IDENT has type 'lens'
   *
   * The point of all this is that we make it possible to put a recursive
   * lens (which is a placeholder for the actual recursion) into arbitrary
   * places in some bigger lens and then have LNS_CHECK_REC rattle through
   * to do the special-purpose typechecking.
   */
  char *id;
  struct info *info = exp->info;
  struct term *lambda = NULL, *rlens = NULL;
  struct term *app1 = NULL, *app2 = NULL, *app3 = NULL;

  id = strdup(ident);
  if (id == NULL) goto error;

  lambda = make_param(id, make_base_type(T_LENS), ref(info));
  if (lambda == NULL) goto error;
  id = NULL;

  build_func(lambda, exp);

  rlens = make_term(A_VALUE, ref(exp->info));
  if (rlens == NULL) goto error;
  rlens->value = lns_make_rec(ref(exp->info));
  if (rlens->value == NULL) goto error;
  rlens->type = make_base_type(T_LENS);

  app1 = make_app_term(lambda, rlens, ref(info));
  if (app1 == NULL) goto error;

  id = strdup(LNS_CHECK_REC_NAME);
  if (id == NULL) goto error;
  app2 = make_app_ident(id, app1, ref(info));
  if (app2 == NULL) goto error;
  id = NULL;

  app3 = make_app_term(app2, ref(rlens), ref(info));
  if (app3 == NULL) goto error;

  return make_bind(ident, NULL, app3, decls, locp);

 error:
  free(id);
  unref(lambda, term);
  unref(rlens, term);
  unref(app1, term);
  unref(app2, term);
  unref(app3, term);
  return NULL;
}

static struct term *make_let(char *ident, struct term *params,
                             struct term *exp, struct term *body,
                             struct info *locp) {
  /* let f (x:string) = "f " . x in
     f "a" . f "b" */
  /* (lambda f: f "a" . f "b") (lambda x: "f " . x) */
  /* (lambda IDENT: BODY) (lambda PARAMS: EXP) */
  /* Desugar as (lambda IDENT: BODY) (lambda PARAMS: EXP) */
  struct term *term = make_term_locp(A_LET, locp);
  struct term *p = make_param(ident, NULL, ref(term->info));
  term->left = build_func(p, body);
  if (params != NULL)
    term->right = build_func(params, exp);
  else
    term->right = exp;
  return term;
}

static struct term *make_binop(enum term_tag tag,
                              struct term *left, struct term *right,
                              struct info *locp) {
  assert(tag == A_COMPOSE || tag == A_CONCAT
         || tag == A_UNION || tag == A_APP || tag == A_MINUS);
  struct term *term = make_term_locp(tag, locp);
  term->left = left;
  term->right = right;
  return term;
}

static struct term *make_unop(enum term_tag tag, struct term *exp,
                             struct info *locp) {
  assert(tag == A_BRACKET);
  struct term *term = make_term_locp(tag, locp);
  term->brexp = exp;
  return term;
}

static struct term *make_ident(char *qname, struct info *locp) {
  struct term *term = make_term_locp(A_IDENT, locp);
  term->ident = make_string(qname);
  return term;
}

static struct term *make_unit_term(struct info *locp) {
  struct term *term = make_term_locp(A_VALUE, locp);
  term->value = make_unit(ref(term->info));
  return term;
}

static struct term *make_string_term(char *value, struct info *locp) {
  struct term *term = make_term_locp(A_VALUE, locp);
  term->value = make_value(V_STRING, ref(term->info));
  term->value->string = make_string(value);
  return term;
}

static struct term *make_regexp_term(char *pattern, int nocase,
                                     struct info *locp) {
  struct term *term = make_term_locp(A_VALUE, locp);
  term->value = make_value(V_REGEXP, ref(term->info));
  term->value->regexp = make_regexp(term->info, pattern, nocase);
  return term;
}

static struct term *make_rep(struct term *exp, enum quant_tag quant,
                            struct info *locp) {
  struct term *term = make_term_locp(A_REP, locp);
  term->quant = quant;
  term->exp = exp;
  return term;
}

static struct term *make_get_test(struct term *lens, struct term *arg,
                                  struct info *locp) {
  /* Return a term for "get" LENS ARG */
  struct info *info = clone_info(locp);
  struct term *term = make_app_ident(strdup("get"), lens, info);
  term = make_app_term(term, arg, ref(info));
  return term;
}

static struct term *make_put_test(struct term *lens, struct term *arg,
                                  struct term *cmds, struct info *locp) {
  /* Return a term for "put" LENS (CMDS ("get" LENS ARG)) ARG */
  struct term *term = make_get_test(lens, arg, locp);
  term = make_app_term(cmds, term, ref(term->info));
  struct term *put = make_app_ident(strdup("put"), ref(lens), ref(term->info));
  put = make_app_term(put, term, ref(term->info));
  put = make_app_term(put, ref(arg), ref(term->info));
  return put;
}

static struct term *make_test(struct term *test, struct term *result,
                              enum test_result_tag tr_tag,
                              struct term *decls, struct info *locp) {
  struct term *term = make_term_locp(A_TEST, locp);
  term->tr_tag = tr_tag;
  term->test = test;
  term->result = result;
  term->next = decls;
  return term;
}

static struct term *make_tree_value(struct tree *tree, struct info *locp) {
  struct term *term = make_term_locp(A_VALUE, locp);
  struct value *value = make_value(V_TREE, ref(term->info));
  value->origin = make_tree_origin(tree);
  term->value = value;
  return term;
}

static struct tree *tree_concat(struct tree *t1, struct tree *t2) {
  if (t2 != NULL)
    list_append(t1, t2);
  return t1;
}

void augl_error(struct info *locp,
                struct term **term,
                yyscan_t scanner,
                const char *s) {
  struct info info;
  struct string string;
  MEMZERO(&info, 1);
  info.ref = string.ref = UINT_MAX;
  info.filename = &string;

  if (locp != NULL) {
    info.first_line   = locp->first_line;
    info.first_column = locp->first_column;
    info.last_line    = locp->last_line;
    info.last_column  = locp->last_column;
    info.filename->str = locp->filename->str;
    info.error = locp->error;
  } else if (scanner != NULL) {
    info.first_line   = augl_get_lineno(scanner);
    info.first_column = augl_get_column(scanner);
    info.last_line    = augl_get_lineno(scanner);
    info.last_column  = augl_get_column(scanner);
    info.filename     = augl_get_info(scanner)->filename;
    info.error        = augl_get_info(scanner)->error;
  } else if (*term != NULL && (*term)->info != NULL) {
    memcpy(&info, (*term)->info, sizeof(info));
  } else {
    info.first_line = info.last_line = 0;
    info.first_column = info.last_column = 0;
  }
  syntax_error(&info, "%s", s);
}
