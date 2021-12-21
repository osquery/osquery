/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

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

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

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

/* First part of user prologue.  */
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

#line 121 "parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

/* Use api.header.include to #include this header
   instead of duplicating it here.  */
#ifndef YY_AUGL_PARSER_H_INCLUDED
# define YY_AUGL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int augl_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    DQUOTED = 258,                 /* DQUOTED  */
    REGEXP = 259,                  /* REGEXP  */
    LIDENT = 260,                  /* LIDENT  */
    UIDENT = 261,                  /* UIDENT  */
    QIDENT = 262,                  /* QIDENT  */
    ARROW = 263,                   /* ARROW  */
    KW_MODULE = 264,               /* KW_MODULE  */
    KW_AUTOLOAD = 265,             /* KW_AUTOLOAD  */
    KW_LET = 266,                  /* KW_LET  */
    KW_LET_REC = 267,              /* KW_LET_REC  */
    KW_IN = 268,                   /* KW_IN  */
    KW_STRING = 269,               /* KW_STRING  */
    KW_REGEXP = 270,               /* KW_REGEXP  */
    KW_LENS = 271,                 /* KW_LENS  */
    KW_TEST = 272,                 /* KW_TEST  */
    KW_GET = 273,                  /* KW_GET  */
    KW_PUT = 274,                  /* KW_PUT  */
    KW_AFTER = 275                 /* KW_AFTER  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif
/* Token kinds.  */
#define YYEMPTY -2
#define YYEOF 0
#define YYerror 256
#define YYUNDEF 257
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

#line 228 "parser.c"

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
#line 46 "parser.y"

#include "info.h"

/* Track custom scanner state */
struct state {
  struct info *info;
  unsigned int comment_depth;
};


#line 267 "parser.c"

#endif /* !YY_AUGL_PARSER_H_INCLUDED  */
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_DQUOTED = 3,                    /* DQUOTED  */
  YYSYMBOL_REGEXP = 4,                     /* REGEXP  */
  YYSYMBOL_LIDENT = 5,                     /* LIDENT  */
  YYSYMBOL_UIDENT = 6,                     /* UIDENT  */
  YYSYMBOL_QIDENT = 7,                     /* QIDENT  */
  YYSYMBOL_ARROW = 8,                      /* ARROW  */
  YYSYMBOL_KW_MODULE = 9,                  /* KW_MODULE  */
  YYSYMBOL_KW_AUTOLOAD = 10,               /* KW_AUTOLOAD  */
  YYSYMBOL_KW_LET = 11,                    /* KW_LET  */
  YYSYMBOL_KW_LET_REC = 12,                /* KW_LET_REC  */
  YYSYMBOL_KW_IN = 13,                     /* KW_IN  */
  YYSYMBOL_KW_STRING = 14,                 /* KW_STRING  */
  YYSYMBOL_KW_REGEXP = 15,                 /* KW_REGEXP  */
  YYSYMBOL_KW_LENS = 16,                   /* KW_LENS  */
  YYSYMBOL_KW_TEST = 17,                   /* KW_TEST  */
  YYSYMBOL_KW_GET = 18,                    /* KW_GET  */
  YYSYMBOL_KW_PUT = 19,                    /* KW_PUT  */
  YYSYMBOL_KW_AFTER = 20,                  /* KW_AFTER  */
  YYSYMBOL_21_ = 21,                       /* '='  */
  YYSYMBOL_22_ = 22,                       /* '?'  */
  YYSYMBOL_23_ = 23,                       /* '*'  */
  YYSYMBOL_24_ = 24,                       /* ';'  */
  YYSYMBOL_25_ = 25,                       /* '|'  */
  YYSYMBOL_26_ = 26,                       /* '-'  */
  YYSYMBOL_27_ = 27,                       /* '.'  */
  YYSYMBOL_28_ = 28,                       /* '('  */
  YYSYMBOL_29_ = 29,                       /* ')'  */
  YYSYMBOL_30_ = 30,                       /* '['  */
  YYSYMBOL_31_ = 31,                       /* ']'  */
  YYSYMBOL_32_ = 32,                       /* '+'  */
  YYSYMBOL_33_ = 33,                       /* ':'  */
  YYSYMBOL_34_ = 34,                       /* '{'  */
  YYSYMBOL_35_ = 35,                       /* '}'  */
  YYSYMBOL_YYACCEPT = 36,                  /* $accept  */
  YYSYMBOL_start = 37,                     /* start  */
  YYSYMBOL_autoload = 38,                  /* autoload  */
  YYSYMBOL_decls = 39,                     /* decls  */
  YYSYMBOL_test_exp = 40,                  /* test_exp  */
  YYSYMBOL_test_special_res = 41,          /* test_special_res  */
  YYSYMBOL_exp = 42,                       /* exp  */
  YYSYMBOL_composeexp = 43,                /* composeexp  */
  YYSYMBOL_unionexp = 44,                  /* unionexp  */
  YYSYMBOL_minusexp = 45,                  /* minusexp  */
  YYSYMBOL_catexp = 46,                    /* catexp  */
  YYSYMBOL_appexp = 47,                    /* appexp  */
  YYSYMBOL_aexp = 48,                      /* aexp  */
  YYSYMBOL_rexp = 49,                      /* rexp  */
  YYSYMBOL_rep = 50,                       /* rep  */
  YYSYMBOL_qid = 51,                       /* qid  */
  YYSYMBOL_param_list = 52,                /* param_list  */
  YYSYMBOL_param = 53,                     /* param  */
  YYSYMBOL_id = 54,                        /* id  */
  YYSYMBOL_type = 55,                      /* type  */
  YYSYMBOL_atype = 56,                     /* atype  */
  YYSYMBOL_tree_const = 57,                /* tree_const  */
  YYSYMBOL_tree_const2 = 58,               /* tree_const2  */
  YYSYMBOL_tree_branch = 59,               /* tree_branch  */
  YYSYMBOL_tree_label = 60                 /* tree_label  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;


/* Second part of user prologue.  */
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


#line 403 "parser.c"


#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_int8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

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


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
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

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

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
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL \
             && defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE) \
             + YYSIZEOF (YYLTYPE)) \
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
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
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

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   275


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
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
static const yytype_int16 yyrline[] =
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

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "DQUOTED", "REGEXP",
  "LIDENT", "UIDENT", "QIDENT", "ARROW", "KW_MODULE", "KW_AUTOLOAD",
  "KW_LET", "KW_LET_REC", "KW_IN", "KW_STRING", "KW_REGEXP", "KW_LENS",
  "KW_TEST", "KW_GET", "KW_PUT", "KW_AFTER", "'='", "'?'", "'*'", "';'",
  "'|'", "'-'", "'.'", "'('", "')'", "'['", "']'", "'+'", "':'", "'{'",
  "'}'", "$accept", "start", "autoload", "decls", "test_exp",
  "test_special_res", "exp", "composeexp", "unionexp", "minusexp",
  "catexp", "appexp", "aexp", "rexp", "rep", "qid", "param_list", "param",
  "id", "type", "atype", "tree_const", "tree_const2", "tree_branch",
  "tree_label", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-90)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-1)

#define yytable_value_is_error(Yyn) \
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
static const yytype_int8 yydefact[] =
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
       0,     2,     7,    12,    23,    71,    33,    34,    35,    36,
      37,    38,    39,    40,    66,    25,    27,    28,    49,    94,
      95,    41,    81,    55,    56
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int8 yytable[] =
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

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
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

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    36,    37,    38,    38,    39,    39,    39,    39,    39,
      40,    40,    41,    41,    42,    42,    43,    43,    44,    44,
      44,    45,    45,    46,    46,    47,    47,    48,    48,    48,
      48,    48,    48,    49,    49,    50,    50,    50,    51,    51,
      51,    51,    52,    52,    53,    54,    54,    54,    55,    55,
      56,    56,    56,    56,    57,    57,    58,    58,    59,    59,
      60,    60
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     5,     2,     0,     6,     5,     5,     5,     0,
       3,     5,     1,     1,     7,     1,     3,     1,     3,     1,
       1,     3,     1,     3,     1,     2,     1,     1,     1,     1,
       3,     3,     2,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     2,     0,     5,     1,     1,     1,     3,     1,
       1,     1,     1,     3,     4,     3,     4,     0,     2,     4,
       1,     0
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
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

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF

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


/* YYLOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

# ifndef YYLOCATION_PRINT

#  if defined YY_LOCATION_PRINT

   /* Temporary convenience wrapper in case some people defined the
      undocumented and private YY_LOCATION_PRINT macros.  */
#   define YYLOCATION_PRINT(File, Loc)  YY_LOCATION_PRINT(File, *(Loc))

#  elif defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static int
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  int res = 0;
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

#   define YYLOCATION_PRINT  yy_location_print_

    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT(File, Loc)  YYLOCATION_PRINT(File, &(Loc))

#  else

#   define YYLOCATION_PRINT(File, Loc) ((void) 0)
    /* Temporary convenience wrapper in case some people defined the
       undocumented and private YY_LOCATION_PRINT macros.  */
#   define YY_LOCATION_PRINT  YYLOCATION_PRINT

#  endif
# endif /* !defined YYLOCATION_PRINT */


# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, Location, term, scanner); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (yylocationp);
  YY_USE (term);
  YY_USE (scanner);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct term **term, yyscan_t scanner)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  YYLOCATION_PRINT (yyo, yylocationp);
  YYFPRINTF (yyo, ": ");
  yy_symbol_value_print (yyo, yykind, yyvaluep, yylocationp, term, scanner);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
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
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp,
                 int yyrule, struct term **term, yyscan_t scanner)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)],
                       &(yylsp[(yyi + 1) - (yynrhs)]), term, scanner);
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
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
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


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
  YYLTYPE *yylloc;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
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
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
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
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
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
            else
              goto append;

          append:
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

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
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
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
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
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct term **term, yyscan_t scanner)
{
  YY_USE (yyvaluep);
  YY_USE (yylocationp);
  YY_USE (term);
  YY_USE (scanner);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct term **term, yyscan_t scanner)
{
/* Lookahead token kind.  */
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
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

    /* The location stack: array, bottom, top.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls = yylsa;
    YYLTYPE *yylsp = yyls;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

  /* The locations where the error started and ended.  */
  YYLTYPE yyerror_range[3];

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */


/* User initialization code.  */
#line 66 "parser.y"
{
  yylloc.first_line   = 1;
  yylloc.first_column = 0;
  yylloc.last_line    = 1;
  yylloc.last_column  = 0;
  yylloc.filename     = augl_get_info(scanner)->filename;
  yylloc.error        = augl_get_info(scanner)->error;
}

#line 1633 "parser.c"

  yylsp[0] = yylloc;
  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yyls1, yysize * YYSIZEOF (*yylsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
        yyls = yyls1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


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

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, &yylloc, scanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      yyerror_range[1] = yylloc;
      goto yyerrlab1;
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
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
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
| yyreduce -- do a reduction.  |
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

  /* Default location. */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  yyerror_range[1] = yyloc;
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 2: /* start: KW_MODULE UIDENT '=' autoload decls  */
#line 180 "parser.y"
       { (*term) = make_module((yyvsp[-3].string), (yyvsp[-1].string), (yyvsp[0].term), &(yylsp[-4])); }
#line 1846 "parser.c"
    break;

  case 3: /* autoload: KW_AUTOLOAD LIDENT  */
#line 183 "parser.y"
          { (yyval.string) = (yyvsp[0].string); }
#line 1852 "parser.c"
    break;

  case 4: /* autoload: %empty  */
#line 185 "parser.y"
          { (yyval.string) = NULL; }
#line 1858 "parser.c"
    break;

  case 5: /* decls: KW_LET LIDENT param_list '=' exp decls  */
#line 188 "parser.y"
       {
         LOC_MERGE((yylsp[-5]), (yylsp[-5]), (yylsp[-1]));
         (yyval.term) = make_bind((yyvsp[-4].string), (yyvsp[-3].term), (yyvsp[-1].term), (yyvsp[0].term), &(yylsp[-5]));
       }
#line 1867 "parser.c"
    break;

  case 6: /* decls: KW_LET_REC LIDENT '=' exp decls  */
#line 193 "parser.y"
       {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_bind_rec((yyvsp[-3].string), (yyvsp[-1].term), (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1876 "parser.c"
    break;

  case 7: /* decls: KW_TEST test_exp '=' exp decls  */
#line 198 "parser.y"
       {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_test((yyvsp[-3].term), (yyvsp[-1].term), TR_CHECK, (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1885 "parser.c"
    break;

  case 8: /* decls: KW_TEST test_exp '=' test_special_res decls  */
#line 203 "parser.y"
       {
         LOC_MERGE((yylsp[-4]), (yylsp[-4]), (yylsp[-1]));
         (yyval.term) = make_test((yyvsp[-3].term), NULL, (yyvsp[-1].intval), (yyvsp[0].term), &(yylsp[-4]));
       }
#line 1894 "parser.c"
    break;

  case 9: /* decls: %empty  */
#line 208 "parser.y"
       { (yyval.term) = NULL; }
#line 1900 "parser.c"
    break;

  case 10: /* test_exp: aexp KW_GET exp  */
#line 213 "parser.y"
          { (yyval.term) = make_get_test((yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1906 "parser.c"
    break;

  case 11: /* test_exp: aexp KW_PUT aexp KW_AFTER exp  */
#line 215 "parser.y"
          { (yyval.term) = make_put_test((yyvsp[-4].term), (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1912 "parser.c"
    break;

  case 12: /* test_special_res: '?'  */
#line 218 "parser.y"
                  { (yyval.intval) = TR_PRINT; }
#line 1918 "parser.c"
    break;

  case 13: /* test_special_res: '*'  */
#line 220 "parser.y"
                  { (yyval.intval) = TR_EXN; }
#line 1924 "parser.c"
    break;

  case 14: /* exp: KW_LET LIDENT param_list '=' exp KW_IN exp  */
#line 224 "parser.y"
     {
       LOC_MERGE((yylsp[-6]), (yylsp[-6]), (yylsp[-1]));
       (yyval.term) = make_let((yyvsp[-5].string), (yyvsp[-4].term), (yyvsp[-2].term), (yyvsp[0].term), &(yylsp[-6]));
     }
#line 1933 "parser.c"
    break;

  case 16: /* composeexp: composeexp ';' unionexp  */
#line 231 "parser.y"
     { (yyval.term) = make_binop(A_COMPOSE, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1939 "parser.c"
    break;

  case 17: /* composeexp: unionexp  */
#line 233 "parser.y"
     { (yyval.term) = (yyvsp[0].term); }
#line 1945 "parser.c"
    break;

  case 18: /* unionexp: unionexp '|' minusexp  */
#line 236 "parser.y"
     { (yyval.term) = make_binop(A_UNION, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1951 "parser.c"
    break;

  case 19: /* unionexp: minusexp  */
#line 238 "parser.y"
     { (yyval.term) = (yyvsp[0].term); }
#line 1957 "parser.c"
    break;

  case 20: /* unionexp: tree_const  */
#line 240 "parser.y"
     { (yyval.term) = make_tree_value((yyvsp[0].tree), &(yylsp[0])); }
#line 1963 "parser.c"
    break;

  case 21: /* minusexp: minusexp '-' catexp  */
#line 243 "parser.y"
     { (yyval.term) = make_binop(A_MINUS, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1969 "parser.c"
    break;

  case 22: /* minusexp: catexp  */
#line 245 "parser.y"
     { (yyval.term) = (yyvsp[0].term); }
#line 1975 "parser.c"
    break;

  case 23: /* catexp: catexp '.' appexp  */
#line 248 "parser.y"
{ (yyval.term) = make_binop(A_CONCAT, (yyvsp[-2].term), (yyvsp[0].term), &(yyloc)); }
#line 1981 "parser.c"
    break;

  case 24: /* catexp: appexp  */
#line 250 "parser.y"
{ (yyval.term) = (yyvsp[0].term); }
#line 1987 "parser.c"
    break;

  case 25: /* appexp: appexp rexp  */
#line 253 "parser.y"
        { (yyval.term) = make_binop(A_APP, (yyvsp[-1].term), (yyvsp[0].term), &(yyloc)); }
#line 1993 "parser.c"
    break;

  case 26: /* appexp: rexp  */
#line 255 "parser.y"
        { (yyval.term) = (yyvsp[0].term); }
#line 1999 "parser.c"
    break;

  case 27: /* aexp: qid  */
#line 258 "parser.y"
      { (yyval.term) = make_ident((yyvsp[0].string), &(yylsp[0])); }
#line 2005 "parser.c"
    break;

  case 28: /* aexp: DQUOTED  */
#line 260 "parser.y"
      { (yyval.term) = make_string_term((yyvsp[0].string), &(yylsp[0])); }
#line 2011 "parser.c"
    break;

  case 29: /* aexp: REGEXP  */
#line 262 "parser.y"
      { (yyval.term) = make_regexp_term((yyvsp[0].regexp).pattern, (yyvsp[0].regexp).nocase, &(yylsp[0])); }
#line 2017 "parser.c"
    break;

  case 30: /* aexp: '(' exp ')'  */
#line 264 "parser.y"
      { (yyval.term) = (yyvsp[-1].term); }
#line 2023 "parser.c"
    break;

  case 31: /* aexp: '[' exp ']'  */
#line 266 "parser.y"
      { (yyval.term) = make_unop(A_BRACKET, (yyvsp[-1].term), &(yyloc)); }
#line 2029 "parser.c"
    break;

  case 32: /* aexp: '(' ')'  */
#line 268 "parser.y"
      { (yyval.term) = make_unit_term(&(yyloc)); }
#line 2035 "parser.c"
    break;

  case 33: /* rexp: aexp rep  */
#line 271 "parser.y"
      { (yyval.term) = make_rep((yyvsp[-1].term), (yyvsp[0].quant), &(yyloc)); }
#line 2041 "parser.c"
    break;

  case 34: /* rexp: aexp  */
#line 273 "parser.y"
      { (yyval.term) = (yyvsp[0].term); }
#line 2047 "parser.c"
    break;

  case 35: /* rep: '*'  */
#line 276 "parser.y"
     { (yyval.quant) = Q_STAR; }
#line 2053 "parser.c"
    break;

  case 36: /* rep: '+'  */
#line 278 "parser.y"
     { (yyval.quant) = Q_PLUS; }
#line 2059 "parser.c"
    break;

  case 37: /* rep: '?'  */
#line 280 "parser.y"
     { (yyval.quant) = Q_MAYBE; }
#line 2065 "parser.c"
    break;

  case 38: /* qid: LIDENT  */
#line 283 "parser.y"
     { (yyval.string) = (yyvsp[0].string); }
#line 2071 "parser.c"
    break;

  case 39: /* qid: QIDENT  */
#line 285 "parser.y"
     { (yyval.string) = (yyvsp[0].string); }
#line 2077 "parser.c"
    break;

  case 40: /* qid: KW_GET  */
#line 287 "parser.y"
     { (yyval.string) = strdup("get"); }
#line 2083 "parser.c"
    break;

  case 41: /* qid: KW_PUT  */
#line 289 "parser.y"
     { (yyval.string) = strdup("put"); }
#line 2089 "parser.c"
    break;

  case 42: /* param_list: param param_list  */
#line 292 "parser.y"
            { (yyval.term) = (yyvsp[0].term); list_cons((yyval.term), (yyvsp[-1].term)); }
#line 2095 "parser.c"
    break;

  case 43: /* param_list: %empty  */
#line 294 "parser.y"
            { (yyval.term) = NULL; }
#line 2101 "parser.c"
    break;

  case 44: /* param: '(' id ':' type ')'  */
#line 297 "parser.y"
       { (yyval.term) = make_param((yyvsp[-3].string), (yyvsp[-1].type), clone_info(&(yylsp[-4]))); }
#line 2107 "parser.c"
    break;

  case 45: /* id: LIDENT  */
#line 300 "parser.y"
    { (yyval.string) = (yyvsp[0].string); }
#line 2113 "parser.c"
    break;

  case 46: /* id: KW_GET  */
#line 302 "parser.y"
    { (yyval.string) = strdup("get"); }
#line 2119 "parser.c"
    break;

  case 47: /* id: KW_PUT  */
#line 304 "parser.y"
    { (yyval.string) = strdup("put"); }
#line 2125 "parser.c"
    break;

  case 48: /* type: atype ARROW type  */
#line 307 "parser.y"
      { (yyval.type) = make_arrow_type((yyvsp[-2].type), (yyvsp[0].type)); }
#line 2131 "parser.c"
    break;

  case 49: /* type: atype  */
#line 309 "parser.y"
      { (yyval.type) = (yyvsp[0].type); }
#line 2137 "parser.c"
    break;

  case 50: /* atype: KW_STRING  */
#line 312 "parser.y"
       { (yyval.type) = make_base_type(T_STRING); }
#line 2143 "parser.c"
    break;

  case 51: /* atype: KW_REGEXP  */
#line 314 "parser.y"
       { (yyval.type) = make_base_type(T_REGEXP); }
#line 2149 "parser.c"
    break;

  case 52: /* atype: KW_LENS  */
#line 316 "parser.y"
       { (yyval.type) = make_base_type(T_LENS); }
#line 2155 "parser.c"
    break;

  case 53: /* atype: '(' type ')'  */
#line 318 "parser.y"
       { (yyval.type) = (yyvsp[-1].type); }
#line 2161 "parser.c"
    break;

  case 54: /* tree_const: tree_const '{' tree_branch '}'  */
#line 321 "parser.y"
            { (yyval.tree) = tree_concat((yyvsp[-3].tree), (yyvsp[-1].tree)); }
#line 2167 "parser.c"
    break;

  case 55: /* tree_const: '{' tree_branch '}'  */
#line 323 "parser.y"
            { (yyval.tree) = tree_concat((yyvsp[-1].tree), NULL); }
#line 2173 "parser.c"
    break;

  case 56: /* tree_const2: tree_const2 '{' tree_branch '}'  */
#line 326 "parser.y"
            {
              (yyval.tree) = tree_concat((yyvsp[-3].tree), (yyvsp[-1].tree));
            }
#line 2181 "parser.c"
    break;

  case 57: /* tree_const2: %empty  */
#line 330 "parser.y"
            { (yyval.tree) = NULL; }
#line 2187 "parser.c"
    break;

  case 58: /* tree_branch: tree_label tree_const2  */
#line 333 "parser.y"
             {
               (yyval.tree) = make_tree((yyvsp[-1].string), NULL, NULL, (yyvsp[0].tree));
             }
#line 2195 "parser.c"
    break;

  case 59: /* tree_branch: tree_label '=' DQUOTED tree_const2  */
#line 337 "parser.y"
             {
               (yyval.tree) = make_tree((yyvsp[-3].string), (yyvsp[-1].string), NULL, (yyvsp[0].tree));
             }
#line 2203 "parser.c"
    break;

  case 61: /* tree_label: %empty  */
#line 342 "parser.y"
            { (yyval.string) = NULL; }
#line 2209 "parser.c"
    break;


#line 2213 "parser.c"

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
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken, &yylloc};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (&yylloc, term, scanner, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
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
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

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

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
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
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, yylsp, term, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  ++yylsp;
  YYLLOC_DEFAULT (*yylsp, yyerror_range, 2);

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, term, scanner, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
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
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, yylsp, term, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

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
