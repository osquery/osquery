/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison interface for Yacc-like parsers in C

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
#line 89 "parser.y" /* yacc.c:1909  */

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

#line 108 "parser.h" /* yacc.c:1909  */
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
#line 46 "parser.y" /* yacc.c:1909  */

#include "info.h"

/* Track custom scanner state */
struct state {
  struct info *info;
  unsigned int comment_depth;
};


#line 145 "parser.h" /* yacc.c:1909  */

#endif /* !YY_AUGL_PARSER_H_INCLUDED  */
