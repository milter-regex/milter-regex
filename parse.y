/* $Id: parse.y,v 1.3 2011/11/24 13:43:27 dhartmei Exp $ */

/*
 * Copyright (c) 2004-2006 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

%{
static const char rcsid[] = "$Id: parse.y,v 1.3 2011/11/24 13:43:27 dhartmei Exp $";

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libmilter/mfapi.h>

#include "eval.h"

int			 yyerror(const char *, ...);
static int		 yyparse(void);
static int		 define_macro(const char *, struct expr *);
static struct expr	*find_macro(const char *);

static char		*err_str = NULL;
static size_t		 err_len = 0;
static const char	*infile = NULL;
static FILE		*fin = NULL;
static int		 lineno = 1;
static int		 errors = 0;
static struct ruleset	*rs = NULL;

struct macro {
	char		*name;
	struct expr	*expr;
	struct macro	*next;
} *macros = NULL;

typedef struct {
	union {
		char			*string;
		struct expr		*expr;
		struct expr_list	*expr_list;
		struct action		*action;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	ERROR STRING
%token	ACCEPT REJECT TEMPFAIL DISCARD QUARANTINE
%token	CONNECT HELO ENVFROM ENVRCPT HEADER MACRO BODY
%token	AND OR NOT
%type	<v.string>	STRING
%type	<v.expr>	expr term
%type	<v.expr_list>	expr_l
%type	<v.action>	action
%%

file	: /* empty */
	| macro file		{ }
	| rule file		{ }
	;

rule	: action expr_l		{
		struct expr_list *el = $2, *eln;

		while (el != NULL) {
			eln = el->next;
			el->expr->action = $1;
			free(el);
			el = eln;
		}
	}
	;

macro	: STRING '=' expr	{
		if (define_macro($1, $3))
			YYERROR;
		free($1);
	}
	;

action	: REJECT STRING		{
		$$ = create_action(rs, ACTION_REJECT, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| TEMPFAIL STRING	{
		$$ = create_action(rs, ACTION_TEMPFAIL, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| QUARANTINE STRING	{
		$$ = create_action(rs, ACTION_QUARANTINE, $2);
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
		free($2);
	}
	| DISCARD 		{
		$$ = create_action(rs, ACTION_DISCARD, "");
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	| ACCEPT 		{
		$$ = create_action(rs, ACTION_ACCEPT, "");
		if ($$ == NULL) {
			yyerror("yyparse: create_action");
			YYERROR;
		}
	}
	;

expr_l	: expr			{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $1;
	}
	| expr_l expr		{
		$$ = calloc(1, sizeof(struct expr_list));
		if ($$ == NULL) {
			yyerror("yyparse: calloc: %s", strerror(errno));
			YYERROR;
		}
		$$->expr = $2;
		$$->next = $1;
	}
	;

expr	: term			{
		$$ = $1;
	}
	| term AND expr	{
		$$ = create_expr(rs, EXPR_AND, $1, $3);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	| term OR expr	{
		$$ = create_expr(rs, EXPR_OR, $1, $3);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	| NOT term		{
		$$ = create_expr(rs, EXPR_NOT, $2, NULL);
		if ($$ == NULL) {
			yyerror("yyparse: create_expr");
			YYERROR;
		}
	}
	;

term	: CONNECT STRING STRING	{
		$$ = create_cond(rs, COND_CONNECT, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| HELO STRING		{
		$$ = create_cond(rs, COND_HELO, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVFROM STRING	{
		$$ = create_cond(rs, COND_ENVFROM, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| ENVRCPT STRING	{
		$$ = create_cond(rs, COND_ENVRCPT, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| HEADER STRING STRING	{
		$$ = create_cond(rs, COND_HEADER, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| MACRO STRING STRING	{
		$$ = create_cond(rs, COND_MACRO, $2, $3);
		if ($$ == NULL)
			YYERROR;
		free($2);
		free($3);
	}
	| BODY STRING		{
		$$ = create_cond(rs, COND_BODY, $2, NULL);
		if ($$ == NULL)
			YYERROR;
		free($2);
	}
	| '(' expr ')'		{
		$$ = $2;
	}
	| '$' STRING		{
		$$ = find_macro($2);
		if ($$ == NULL) {
			yyerror("yyparse: undefined macro '%s'", $2);
			YYERROR;
		}
		free($2);
	}
	;

%%

int
yyerror(const char *fmt, ...)
{
	va_list ap;
	errors = 1;

	if (err_str == NULL || err_len <= 0)
		return (0);
	va_start(ap, fmt);
	snprintf(err_str, err_len, "%s:%d: ", infile, yylval.lineno);
	vsnprintf(err_str + strlen(err_str), err_len - strlen(err_str),
	    fmt, ap);
	va_end(ap);
	return (0);
}

struct keywords {
	const char	*k_name;
	int		 k_val;
};

static int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((struct keywords *)e)->k_name));
}

static int
lookup(char *s)
{
	/* keep sorted */
	static const struct keywords keywords[] = {
		{ "accept",	ACCEPT },
		{ "and",	AND },
		{ "body",	BODY },
		{ "connect",	CONNECT },
		{ "discard",	DISCARD },
		{ "envfrom",	ENVFROM },
		{ "envrcpt",	ENVRCPT },
		{ "header",	HEADER },
		{ "helo",	HELO },
		{ "macro",	MACRO },
		{ "not",	NOT },
		{ "or",		OR },
		{ "quarantine",	QUARANTINE },
		{ "reject",	REJECT },
		{ "tempfail",	TEMPFAIL },
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords) / sizeof(keywords[0]),
	    sizeof(keywords[0]), &kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

static int
lgetc(FILE *fin)
{
	int c, next;

restart:
	c = getc(fin);
	if (c == '\\') {
		next = getc(fin);
		if (next != '\n') {
			ungetc(next, fin);
			return (c);
		}
		yylval.lineno = lineno;
		lineno++;
		goto restart;
	}
	return (c);
}

static int
lungetc(int c, FILE *fin)
{
	return ungetc(c, fin);
}

int
yylex(void)
{
	int c;

top:
	yylval.lineno = lineno;

	while ((c = lgetc(fin)) == ' ' || c == '\t')
		;

	if (c == '#')
		while ((c = lgetc(fin)) != '\n' && c != EOF)
			;

	if (c == '\"' || c == '\'') {
		char del = c;
		char buf[8192], *p = buf;

		while ((c = lgetc(fin)) != EOF && c != del) {
			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf) - 1) {
				yyerror("yylex: message too long");
				return (ERROR);
			}
		}
		*p = 0;
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL) {
			yyerror("yylex: strdup: %s", strerror(errno));
			return (ERROR);
		}
		return (STRING);
	}

	if (isalpha(c)) {
		char buf[8192], *p = buf;
		int token;

		do {
			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf)) {
				yyerror("yylex: token too long");
				return (ERROR);
			}
		} while ((c = lgetc(fin)) != EOF &&
		    (isalpha(c) || isdigit(c) || ispunct(c)));
		lungetc(c, fin);
		*p = 0;
		token = lookup(buf);
		if (token == STRING) {
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL) {
				yyerror("yylex: strdup: %s", strerror(errno));
				return (ERROR);
			}
		}
		return (token);
	}

	if (c != '\n' && c != '(' && c != ')' && c != '=' && c != '$' &&
	    c != EOF) {
		char del = c;
		char buf[8192], *p = buf;

		*p++ = del;
		while ((c = lgetc(fin)) != EOF && c != '\n' && c != del) {
			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf) - 1) {
				yyerror("yylex: argument too long");
				return (ERROR);
			}
		}
		if (c != EOF && c != '\n') {
			*p++ = del;
			while ((c = lgetc(fin)) != EOF && isalpha(c)) {
				*p++ = c;
				if ((size_t)(p - buf) >= sizeof(buf)) {
					yyerror("yylex: argument too long");
					return (ERROR);
				}
			}
		}
		if (c != EOF)
			lungetc(c, fin);
		*p = 0;
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL) {
			yyerror("yylex: strdup: %s", strerror(errno));
			return (ERROR);
		}
		return (STRING);
	}

	if (c == '\n') {
		lineno++;
		goto top;
	}

	if (c == EOF)
		return (0);

	return (c);
}

int
parse_ruleset(const char *f, struct ruleset **r, char *err, size_t len)
{
	*r = NULL;
	err_str = err;
	err_len = len;
	rs = create_ruleset();
	if (rs == NULL) {
		if (err_str != NULL && err_len > 0)
			snprintf(err_str, err_len, "create_ruleset");
		return (1);
	}
	infile = f;
	fin = fopen(infile, "rb");
	if (fin == NULL) {
		if (err_str != NULL && err_len > 0)
			snprintf(err_str, err_len, "fopen: %s: %s",
			    infile, strerror(errno));
		return (1);
	}
	lineno = 1;
	errors = 0;
	yyparse();
	fclose(fin);
	while (macros != NULL) {
		struct macro *m = macros->next;

		free(macros->name);
		free(macros);
		macros = m;
	}
	if (errors) {
		free_ruleset(rs);
		return (1);
	} else {
		*r = rs;
		return (0);
	}
}

static int
define_macro(const char *name, struct expr *e)
{
	struct macro *m = macros;

	while (m != NULL && strcmp(m->name, name))
		m = m->next;
	if (m != NULL) {
		yyerror("define_macro: macro '%s' already defined", name);
		return (1);
	}
	m = calloc(1, sizeof(struct macro));
	if (m == NULL) {
		yyerror("define_macro: calloc: %s", strerror(errno));
		return (1);
	}
	m->name = strdup(name);
	if (m->name == NULL) {
		yyerror("define_macro: strdup: %s", strerror(errno));
		free(m);
		return (1);
	}
	m->expr = e;
	m->next = macros;
	macros = m;
	return (0);
}

static struct expr *
find_macro(const char *name)
{
	struct macro *m = macros;

	while (m != NULL && strcmp(m->name, name))
		m = m->next;
	if (m == NULL)
		return (NULL);
	return (m->expr);
}
