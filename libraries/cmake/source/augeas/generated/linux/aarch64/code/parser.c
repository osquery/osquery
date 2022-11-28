/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

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
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         augl_parse
#define yylex           augl_lex
#define yyerror         augl_error
#define yydebug         augl_debug
#define yynerrs         augl_nerrs


/* Copy the first part of user declarations.  */
#line 1 "parser.y" /* yacc.c:339  */


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

#line 117 "parser.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* In a future release of Bison, this section will be replaced
   by #include "y.tab.h".  */
#ifndef YY_AUGL_PARSER_H_INCLUDED
# define YY_AUGL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int augl_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
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

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED

union YYSTYPE
{
#line 89 "parser.y" /* yacc.c:355  */

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

#line 211 "parser.c" /* yacc.c:355  */
};

typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined YYLTYPE && ! defined YYLTYPE_IS_DECLARED
typedef struct YYLTYPE YYLTYPE;
struct YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define YYLTYPE_IS_DECLARED 1
# define YYLTYPE_IS_TRIVIAL 1
#endif



int augl_parse (struct term **term, yyscan_t scanner);
/* "%code provides" blocks.  */
#line 46 "parser.y" /* yacc.c:355  */

#include "info.h"

/* Track custom scanner state */
struct state {
  struct info *info;
  unsigned int comment_depth;
};


#line 248 "parser.c" /* yacc.c:355  */

#endif /* !YY_AUGL_PARSER_H_INCLUDED  */

/* Copy the second part of user declarations.  */
#line 114 "parser.y" /* yacc.c:358  */

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


#line 316 "parser.c" /* yacc.c:358  */

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
#else
typedef signed char yytype_int8;
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
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
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
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
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
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
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

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

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
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  113

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   275

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
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
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
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

#if YYDEBUG || YYERROR_VERBOSE || 1
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
  "tree_const2", "tree_branch", "tree_label", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,    61,    63,    42,    59,   124,    45,    46,    40,    41,
      91,    93,    43,    58,   123,   125
};
# endif

#define YYPACT_NINF -90

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-90)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
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

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
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

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -90,   -90,   -90,   -34,   -90,   -90,   -22,   -90,    61,    66,
      58,    62,    -9,   -37,   -90,   -90,   -23,   -90,   -90,   -89,
     -90,   -90,    31,   -64,   -90
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     2,     7,    12,    23,    71,    33,    34,    35,    36,
      37,    38,    39,    40,    66,    25,    27,    28,    49,    94,
      95,    41,    81,    55,    56
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
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

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
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


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (&yylloc, term, scanner, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static unsigned
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  unsigned res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
 }

#  define YY_LOCATION_PRINT(File, Loc)          \
  yy_location_print_ (File, &(Loc))

# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, Location, term, scanner); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yylocationp);
  YYUSE (term);
  YYUSE (scanner);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, term, scanner);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule, struct term **term, yyscan_t scanner)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                       , &(yylsp[(yyi + 1) - (yynrhs)])                       , term, scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, term, scanner); \
} while (0)

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
#ifndef YYINITDEPTH
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
static YYSIZE_T
yystrlen (const char *yystr)
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
static char *
yystpcpy (char *yydest, const char *yysrc)
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

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct term **term, yyscan_t scanner)
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  YYUSE (term);
  YYUSE (scanner);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct term **term, yyscan_t scanner)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.
       'yyls': related to locations.

       Refer to the stacks through separate pointers, to allow yyoverflow
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
    YYLTYPE yyerror_range[3];

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
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

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yylsp = yyls = yylsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

/* User initialization code.  */
#line 66 "parser.y" /* yacc.c:1429  */
{
  yylloc.first_line   = 1;
  yylloc.first_column = 0;
  yylloc.last_line    = 1;
  yylloc.last_column  = 0;
  yylloc.filename     = augl_get_info(scanner)->filename;
  yylloc.error        = augl_get_info(scanner)->error;
}

#line 1401 "parser.c" /* yacc.c:1429  */
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
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, &yylloc, scanner);
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
      if (yytable_value_is_error (yyn))
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
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
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
     '$$ = $1'.

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
#line 180 "parser.y" /* yacc.c:1646  */
    { (*term) = make_module((yyvsp[-3].string), (yyvsp[-1].string), (yyvsp[0].term), &(yylsp[-4])); }
#line 1590 "parser.c" /* yacc.c:1646  */
    break;

  case 3:
#line 183 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[0].string); }
#line 1596 "parser.c" /* yacc.c:1646  */
    break;

  case 4:
#line 185 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = NULL; }
#line 1602 "parser.c" /* yacc.c:1646  */
    break;

  case 5:
#line 188 "parser.y" /* yacc.c:1646  */
    {
         LOC_MERGE((yylsp[-5]), (yylsp[-5]), (yylsp[-1]));
         (yyval.term) = make_bind((yyvsp[-4].string), (yyvsp[-3].term), (yyvsp[-1].term), (yyvsp[0].term), &(yylsp[-5]));
       }
#line 1611 "parser.c" /* yacc.c:1646  */
    break;

  case 6:
#line 193 "parser.y" /* yacc.c:1646  */
    {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_bind_rec((yyvsp[-3].string), (yyvsp[-1].term), (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1620 "parser.c" /* yacc.c:1646  */
    break;

  case 7:
#line 198 "parser.y" /* yacc.c:1646  */
    {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_test((yyvsp[-3].term), (yyvsp[-1].term), TR_CHECK, (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1629 "parser.c" /* yacc.c:1646  */
    break;

  case 8:
#line 203 "parser.y" /* yacc.c:1646  */
    {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_test((yyvsp[-3].term), NULL, (yyvsp[-1].intval), (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1638 "parser.c" /* yacc.c:1646  */
    break;

  case 9:
#line 208 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = NULL; }
#line 1644 "parser.c" /* yacc.c:1646  */
    break;

  case 10:
#line 213 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_get_test((yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1650 "parser.c" /* yacc.c:1646  */
    break;

  case 11:
#line 215 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_put_test((yyvsp[-4].term), (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1656 "parser.c" /* yacc.c:1646  */
    break;

  case 12:
#line 218 "parser.y" /* yacc.c:1646  */
    { (yyval.intval) = TR_PRINT; }
#line 1662 "parser.c" /* yacc.c:1646  */
    break;

  case 13:
#line 220 "parser.y" /* yacc.c:1646  */
    { (yyval.intval) = TR_EXN; }
#line 1668 "parser.c" /* yacc.c:1646  */
    break;

  case 14:
#line 224 "parser.y" /* yacc.c:1646  */
    {
       LOC_MERGE((yylsp[-6]), (yylsp[-6]), (yylsp[-1]));
       (yyval.term) = make_let((yyvsp[-5].string), (yyvsp[-4].term), (yyvsp[-2].term), (yyvsp[0].term), &(yylsp[-6]));
     }
#line 1677 "parser.c" /* yacc.c:1646  */
    break;

  case 16:
#line 231 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_binop(A_COMPOSE, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1683 "parser.c" /* yacc.c:1646  */
    break;

  case 17:
#line 233 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1689 "parser.c" /* yacc.c:1646  */
    break;

  case 18:
#line 236 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_binop(A_UNION, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1695 "parser.c" /* yacc.c:1646  */
    break;

  case 19:
#line 238 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1701 "parser.c" /* yacc.c:1646  */
    break;

  case 20:
#line 240 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_tree_value((yyvsp[0].tree), &(yylsp[0])); }
#line 1707 "parser.c" /* yacc.c:1646  */
    break;

  case 21:
#line 243 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_binop(A_MINUS, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1713 "parser.c" /* yacc.c:1646  */
    break;

  case 22:
#line 245 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1719 "parser.c" /* yacc.c:1646  */
    break;

  case 23:
#line 248 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_binop(A_CONCAT, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1725 "parser.c" /* yacc.c:1646  */
    break;

  case 24:
#line 250 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1731 "parser.c" /* yacc.c:1646  */
    break;

  case 25:
#line 253 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_binop(A_APP, (yyvsp[-1].term), (yyvsp[0].term), &(yyloc)); }
#line 1737 "parser.c" /* yacc.c:1646  */
    break;

  case 26:
#line 255 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1743 "parser.c" /* yacc.c:1646  */
    break;

  case 27:
#line 258 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_ident((yyvsp[0].string), &(yylsp[0])); }
#line 1749 "parser.c" /* yacc.c:1646  */
    break;

  case 28:
#line 260 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_string_term((yyvsp[0].string), &(yylsp[0])); }
#line 1755 "parser.c" /* yacc.c:1646  */
    break;

  case 29:
#line 262 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_regexp_term((yyvsp[0].regexp).pattern, (yyvsp[0].regexp).nocase, &(yylsp[0])); }
#line 1761 "parser.c" /* yacc.c:1646  */
    break;

  case 30:
#line 264 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[-1].term); }
#line 1767 "parser.c" /* yacc.c:1646  */
    break;

  case 31:
#line 266 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_unop(A_BRACKET, (yyvsp[-1].term), &(yyloc)); }
#line 1773 "parser.c" /* yacc.c:1646  */
    break;

  case 32:
#line 268 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_unit_term(&(yyloc)); }
#line 1779 "parser.c" /* yacc.c:1646  */
    break;

  case 33:
#line 271 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_rep((yyvsp[-1].term), (yyvsp[0].quant), &(yyloc)); }
#line 1785 "parser.c" /* yacc.c:1646  */
    break;

  case 34:
#line 273 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); }
#line 1791 "parser.c" /* yacc.c:1646  */
    break;

  case 35:
#line 276 "parser.y" /* yacc.c:1646  */
    { (yyval.quant) = Q_STAR; }
#line 1797 "parser.c" /* yacc.c:1646  */
    break;

  case 36:
#line 278 "parser.y" /* yacc.c:1646  */
    { (yyval.quant) = Q_PLUS; }
#line 1803 "parser.c" /* yacc.c:1646  */
    break;

  case 37:
#line 280 "parser.y" /* yacc.c:1646  */
    { (yyval.quant) = Q_MAYBE; }
#line 1809 "parser.c" /* yacc.c:1646  */
    break;

  case 38:
#line 283 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[0].string); }
#line 1815 "parser.c" /* yacc.c:1646  */
    break;

  case 39:
#line 285 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[0].string); }
#line 1821 "parser.c" /* yacc.c:1646  */
    break;

  case 40:
#line 287 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = strdup("get"); }
#line 1827 "parser.c" /* yacc.c:1646  */
    break;

  case 41:
#line 289 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = strdup("put"); }
#line 1833 "parser.c" /* yacc.c:1646  */
    break;

  case 42:
#line 292 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = (yyvsp[0].term); list_cons((yyval.term), (yyvsp[-1].term)); }
#line 1839 "parser.c" /* yacc.c:1646  */
    break;

  case 43:
#line 294 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = NULL; }
#line 1845 "parser.c" /* yacc.c:1646  */
    break;

  case 44:
#line 297 "parser.y" /* yacc.c:1646  */
    { (yyval.term) = make_param((yyvsp[-3].string), (yyvsp[-1].type), clone_info(&(yylsp[-4]))); }
#line 1851 "parser.c" /* yacc.c:1646  */
    break;

  case 45:
#line 300 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = (yyvsp[0].string); }
#line 1857 "parser.c" /* yacc.c:1646  */
    break;

  case 46:
#line 302 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = strdup("get"); }
#line 1863 "parser.c" /* yacc.c:1646  */
    break;

  case 47:
#line 304 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = strdup("put"); }
#line 1869 "parser.c" /* yacc.c:1646  */
    break;

  case 48:
#line 307 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = make_arrow_type((yyvsp[-2].type), (yyvsp[0].type)); }
#line 1875 "parser.c" /* yacc.c:1646  */
    break;

  case 49:
#line 309 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[0].type); }
#line 1881 "parser.c" /* yacc.c:1646  */
    break;

  case 50:
#line 312 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = make_base_type(T_STRING); }
#line 1887 "parser.c" /* yacc.c:1646  */
    break;

  case 51:
#line 314 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = make_base_type(T_REGEXP); }
#line 1893 "parser.c" /* yacc.c:1646  */
    break;

  case 52:
#line 316 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = make_base_type(T_LENS); }
#line 1899 "parser.c" /* yacc.c:1646  */
    break;

  case 53:
#line 318 "parser.y" /* yacc.c:1646  */
    { (yyval.type) = (yyvsp[-1].type); }
#line 1905 "parser.c" /* yacc.c:1646  */
    break;

  case 54:
#line 321 "parser.y" /* yacc.c:1646  */
    { (yyval.tree) = tree_concat((yyvsp[-3].tree), (yyvsp[-1].tree)); }
#line 1911 "parser.c" /* yacc.c:1646  */
    break;

  case 55:
#line 323 "parser.y" /* yacc.c:1646  */
    { (yyval.tree) = tree_concat((yyvsp[-1].tree), NULL); }
#line 1917 "parser.c" /* yacc.c:1646  */
    break;

  case 56:
#line 326 "parser.y" /* yacc.c:1646  */
    {
              (yyval.tree) = tree_concat((yyvsp[-3].tree), (yyvsp[-1].tree));
            }
#line 1925 "parser.c" /* yacc.c:1646  */
    break;

  case 57:
#line 330 "parser.y" /* yacc.c:1646  */
    { (yyval.tree) = NULL; }
#line 1931 "parser.c" /* yacc.c:1646  */
    break;

  case 58:
#line 333 "parser.y" /* yacc.c:1646  */
    {
               (yyval.tree) = make_tree((yyvsp[-1].string), NULL, NULL, (yyvsp[0].tree));
             }
#line 1939 "parser.c" /* yacc.c:1646  */
    break;

  case 59:
#line 337 "parser.y" /* yacc.c:1646  */
    {
               (yyval.tree) = make_tree((yyvsp[-3].string), (yyvsp[-1].string), NULL, (yyvsp[0].tree));
             }
#line 1947 "parser.c" /* yacc.c:1646  */
    break;

  case 61:
#line 342 "parser.y" /* yacc.c:1646  */
    { (yyval.string) = NULL; }
#line 1953 "parser.c" /* yacc.c:1646  */
    break;


#line 1957 "parser.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (&yylloc, term, scanner, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (&yylloc, term, scanner, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }

  yyerror_range[1] = yylloc;

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

  yyerror_range[1] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule whose action triggered
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
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
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

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, yylsp, term, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the lookahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, yyerror_range, 2);
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

#if !defined yyoverflow || YYERROR_VERBOSE
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
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, term, scanner);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
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
  return yyresult;
}
#line 343 "parser.y" /* yacc.c:1906  */


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
