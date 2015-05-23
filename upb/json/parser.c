
#line 1 "upb/json/parser.rl"
/*
 * upb - a minimalist implementation of protocol buffers.
 *
 * Copyright (c) 2014 Google Inc.  See LICENSE for details.
 * Author: Josh Haberman <jhaberman@gmail.com>
 *
 * A parser that uses the Ragel State Machine Compiler to generate
 * the finite automata.
 *
 * Ragel only natively handles regular languages, but we can manually
 * program it a bit to handle context-free languages like JSON, by using
 * the "fcall" and "fret" constructs.
 *
 * This parser can handle the basics, but needs several things to be fleshed
 * out:
 *
 * - handling of unicode escape sequences (including high surrogate pairs).
 * - properly check and report errors for unknown fields, stack overflow,
 *   improper array nesting (or lack of nesting).
 * - handling of base64 sequences with padding characters.
 * - handling of push-back (non-success returns from sink functions).
 * - handling of keys/escape-sequences/etc that span input buffers.
 */

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "upb/json/parser.h"

#define UPB_JSON_MAX_DEPTH 64

struct upb_json_parser {
  upb_env *env;
  upb_byteshandler input_handler_;
  upb_bytessink input_;

  // Stack of sinks.
  upb_sink stack[UPB_JSON_MAX_DEPTH];
  upb_sink *top;
  upb_sink *limit;

  // Ragel's internal parsing stack for the parsing state machine.
  int current_state;
  int parser_stack[UPB_JSON_MAX_DEPTH];
  int parser_top;

  // The handle for the current buffer.
  const upb_bufhandle *handle;

  // Intermediate result of parsing a unicode escape sequence.
  uint32_t digit;

  // Selector for whatever string field we are currently parsing into.
  upb_selector_t string_selector;

  union {
    // The beginning of the text buffer we are currently capturing to push as
    // string data to string_selector.  NULL if we are not currently capturing.
    const char *text_start;

    // Active when parser is suspended: how many bytes of the *next* buffer
    // should be immediately pushed as string data to string_selector:
    //
    //   >0: N bytes
    //    0: 0 bytes, but next bytes are in a string.
    //   <0: next bytes are *not* in a string.
    //
    // TODO(haberman): this behavior assumes that the user will give us
    // identical bytes next time they call us.  Is this ok to rely on?  If we
    // don't rely on this, we need the ability to back up our parse state, which
    // is more complicated (maybe as simple as preserving the current state of
    // the beginning of the string).
    int32_t string_bytes;
  } u;
};

static bool check_stack(upb_json_parser *p) {
  if ((p->top + 1) == p->limit) {
    upb_status status = UPB_STATUS_INIT;
    upb_status_seterrmsg(&status, "Nesting too deep");
    upb_env_reporterror(p->env, &status);
    return false;
  }

  return true;
}

static void start_text(upb_json_parser *p, const char *start) {
  p->u.text_start = start;
}

static bool end_text(upb_json_parser *p, const char *end,
                     const upb_bufhandle *bufhandle) {
  assert(p->u.text_start && p->u.text_start != &suspend_text);
  size_t len = end - p->u.text_start;
  size_t consumed = upb_sink_putstring(
      p->top, p->string_selector, p->u.text_start, len, bufhandle);
  assert(consumed < len);
  if (consumed != len) {
    p->u.text_start += consumed;
    return false;
  } else {
    p->u.text_start = NULL;
    return true;
  }
}

static char escape_char(char in) {
  switch (in) {
    case 'r': return '\r';
    case 't': return '\t';
    case 'n': return '\n';
    case 'f': return '\f';
    case 'b': return '\b';
    case '/': return '/';
    case '"': return '"';
    case '\\': return '\\';
    default:
      assert(0);
      return 'x';
  }
}

static bool escape(upb_json_parser *p, const char *ptr) {
  char ch = escape_char(*ptr);
  return upb_sink_putstring(p->top, p->string_selector, &ch, 1, NULL);
}

static void start_hex(upb_json_parser *p) {
  p->digit = 0;
}

static void hexdigit(upb_json_parser *p, const char *ptr) {
  char ch = *ptr;

  p->digit <<= 4;

  if (ch >= '0' && ch <= '9') {
    p->digit += (ch - '0');
  } else if (ch >= 'a' && ch <= 'f') {
    p->digit += ((ch - 'a') + 10);
  } else {
    assert(ch >= 'A' && ch <= 'F');
    p->digit += ((ch - 'A') + 10);
  }
}

static bool end_hex(upb_json_parser *p) {
  uint32_t codepoint = p->digit;

  // emit the codepoint as UTF-8.
  char utf8[3]; // support \u0000 -- \uFFFF -- need only three bytes.
  int length = 0;
  if (codepoint <= 0x7F) {
    utf8[0] = codepoint;
    length = 1;
  } else if (codepoint <= 0x07FF) {
    utf8[1] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[0] = (codepoint & 0x1F) | 0xC0;
    length = 2;
  } else /* codepoint <= 0xFFFF */ {
    utf8[2] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[1] = (codepoint & 0x3F) | 0x80;
    codepoint >>= 6;
    utf8[0] = (codepoint & 0x0F) | 0xE0;
    length = 3;
  }
  // TODO(haberman): Handle high surrogates: if codepoint is a high surrogate
  // we have to wait for the next escape to get the full code point).

  return upb_sink_putstring(p->top, p->string_selector, utf8, length, NULL);
}

/* The actual parser **********************************************************/

// What follows is the Ragel parser itself.  The language is specified in Ragel
// and the actions call our C functions above.
//
// Ragel has an extensive set of functionality, and we use only a small part of
// it.  There are many action types but we only use a few:
//
//   ">" -- transition into a machine
//   "%" -- transition out of a machine
//   "@" -- transition into a final state of a machine.
//
// "@" transitions are tricky because a machine can transition into a final
// state repeatedly.  But in some cases we know this can't happen, for example
// a string which is delimited by a final '"' can only transition into its
// final state once, when the closing '"' is seen.

#define TRY(expr) { \
  upb_sink *sink = parser->top; \
  UPB_UNUSED(sink); \
  if (!(expr)) goto error; }

#define TRY_POP(expr) { \
  assert(parser->top > parser->stack); \
  upb_sink *sink = parser->top - 1; \
  if (!(expr)) goto error; \
  parser->top--; }

#define TRY_PUSH(expr) { \
  if (!check_stack(parser)) goto error; \
  upb_sink *sink = parser->top; \
  upb_sink *subsink = parser->top + 1; \
  if (!(expr)) goto error; \
  parser->top++; }

#define S(sym) SEL_UPB_JSON_ ## sym


#line 355 "upb/json/parser.rl"



#line 225 "upb/json/parser.c"
static const char _json_actions[] = {
	0, 1, 0, 1, 1, 1, 3, 1, 
	4, 1, 6, 1, 7, 1, 8, 1, 
	9, 1, 11, 1, 12, 1, 14, 1, 
	16, 1, 17, 1, 19, 1, 20, 1, 
	21, 1, 23, 1, 27, 1, 35, 1, 
	36, 2, 4, 9, 2, 5, 6, 2, 
	7, 3, 2, 7, 9, 2, 13, 10, 
	2, 15, 11, 2, 16, 17, 2, 17, 
	19, 2, 18, 12, 2, 18, 19, 2, 
	20, 11, 2, 21, 23, 2, 25, 36, 
	2, 28, 36, 2, 29, 36, 2, 30, 
	36, 2, 32, 36, 2, 34, 36, 2, 
	35, 31, 3, 12, 13, 10, 3, 16, 
	17, 19, 3, 35, 24, 2, 3, 35, 
	26, 10, 3, 35, 33, 22, 4, 18, 
	12, 13, 10
};

static const unsigned char _json_key_offsets[] = {
	0, 0, 4, 9, 14, 15, 19, 24, 
	29, 34, 38, 42, 46, 49, 52, 54, 
	58, 62, 64, 66, 71, 73, 75, 84, 
	90, 96, 102, 108, 110, 119, 120, 120, 
	120, 125, 130, 135, 140, 145, 145, 146, 
	147, 148, 149, 149, 150, 151, 152, 152, 
	153, 154, 155, 155, 160, 165, 166, 170, 
	175, 180, 185, 189, 193, 193, 196, 196, 
	196
};

static const char _json_trans_keys[] = {
	32, 123, 9, 13, 32, 34, 125, 9, 
	13, 32, 34, 125, 9, 13, 34, 32, 
	58, 9, 13, 32, 93, 125, 9, 13, 
	32, 44, 125, 9, 13, 32, 44, 125, 
	9, 13, 32, 34, 9, 13, 32, 34, 
	9, 13, 45, 48, 49, 57, 48, 49, 
	57, 46, 69, 101, 48, 57, 69, 101, 
	48, 57, 43, 45, 48, 57, 48, 57, 
	48, 57, 46, 69, 101, 48, 57, 34, 
	92, 34, 92, 34, 47, 92, 98, 102, 
	110, 114, 116, 117, 48, 57, 65, 70, 
	97, 102, 48, 57, 65, 70, 97, 102, 
	48, 57, 65, 70, 97, 102, 48, 57, 
	65, 70, 97, 102, 34, 92, 34, 45, 
	91, 102, 110, 116, 123, 48, 57, 34, 
	32, 93, 125, 9, 13, 32, 44, 93, 
	9, 13, 32, 44, 93, 9, 13, 32, 
	93, 125, 9, 13, 32, 93, 125, 9, 
	13, 97, 108, 115, 101, 117, 108, 108, 
	114, 117, 101, 32, 34, 125, 9, 13, 
	32, 34, 125, 9, 13, 34, 32, 58, 
	9, 13, 32, 93, 125, 9, 13, 32, 
	44, 125, 9, 13, 32, 44, 125, 9, 
	13, 32, 34, 9, 13, 32, 34, 9, 
	13, 32, 9, 13, 0
};

static const char _json_single_lengths[] = {
	0, 2, 3, 3, 1, 2, 3, 3, 
	3, 2, 2, 2, 1, 3, 0, 2, 
	2, 0, 0, 3, 2, 2, 9, 0, 
	0, 0, 0, 2, 7, 1, 0, 0, 
	3, 3, 3, 3, 3, 0, 1, 1, 
	1, 1, 0, 1, 1, 1, 0, 1, 
	1, 1, 0, 3, 3, 1, 2, 3, 
	3, 3, 2, 2, 0, 1, 0, 0, 
	0
};

static const char _json_range_lengths[] = {
	0, 1, 1, 1, 0, 1, 1, 1, 
	1, 1, 1, 1, 1, 0, 1, 1, 
	1, 1, 1, 1, 0, 0, 0, 3, 
	3, 3, 3, 0, 1, 0, 0, 0, 
	1, 1, 1, 1, 1, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 1, 0, 1, 1, 
	1, 1, 1, 1, 0, 1, 0, 0, 
	0
};

static const short _json_index_offsets[] = {
	0, 0, 4, 9, 14, 16, 20, 25, 
	30, 35, 39, 43, 47, 50, 54, 56, 
	60, 64, 66, 68, 73, 76, 79, 89, 
	93, 97, 101, 105, 108, 117, 119, 120, 
	121, 126, 131, 136, 141, 146, 147, 149, 
	151, 153, 155, 156, 158, 160, 162, 163, 
	165, 167, 169, 170, 175, 180, 182, 186, 
	191, 196, 201, 205, 209, 210, 213, 214, 
	215
};

static const char _json_indicies[] = {
	0, 2, 0, 1, 3, 4, 5, 3, 
	1, 6, 7, 8, 6, 1, 9, 1, 
	10, 11, 10, 1, 11, 1, 1, 11, 
	12, 13, 14, 15, 13, 1, 16, 17, 
	18, 16, 1, 19, 7, 19, 1, 20, 
	21, 20, 1, 22, 23, 24, 1, 25, 
	26, 1, 28, 29, 29, 27, 30, 1, 
	29, 29, 30, 27, 31, 31, 32, 1, 
	32, 1, 32, 27, 28, 29, 29, 26, 
	27, 34, 35, 33, 37, 38, 36, 39, 
	39, 39, 39, 39, 39, 39, 39, 40, 
	1, 41, 41, 41, 1, 42, 42, 42, 
	1, 43, 43, 43, 1, 44, 44, 44, 
	1, 46, 47, 45, 48, 49, 50, 51, 
	52, 53, 54, 49, 1, 55, 1, 56, 
	57, 59, 60, 1, 59, 58, 61, 62, 
	63, 61, 1, 64, 65, 60, 64, 1, 
	66, 1, 1, 66, 58, 68, 1, 1, 
	68, 67, 69, 70, 1, 71, 1, 72, 
	1, 73, 1, 74, 75, 1, 76, 1, 
	77, 1, 78, 79, 1, 80, 1, 81, 
	1, 82, 83, 84, 85, 83, 1, 86, 
	87, 88, 86, 1, 89, 1, 90, 91, 
	90, 1, 91, 1, 1, 91, 92, 93, 
	94, 95, 93, 1, 96, 97, 98, 96, 
	1, 99, 87, 99, 1, 100, 101, 100, 
	1, 102, 103, 103, 1, 1, 1, 1, 
	0
};

static const char _json_trans_targs[] = {
	1, 0, 2, 3, 4, 61, 3, 4, 
	61, 5, 5, 6, 7, 8, 9, 61, 
	8, 9, 61, 10, 10, 4, 12, 13, 
	19, 13, 19, 62, 14, 16, 15, 17, 
	18, 21, 63, 22, 21, 63, 22, 20, 
	23, 24, 25, 26, 27, 21, 63, 22, 
	29, 31, 32, 38, 43, 47, 51, 30, 
	64, 64, 33, 32, 37, 34, 35, 37, 
	34, 35, 36, 33, 36, 64, 39, 40, 
	41, 42, 64, 44, 45, 46, 64, 48, 
	49, 50, 64, 52, 53, 60, 52, 53, 
	60, 54, 54, 55, 56, 57, 58, 60, 
	57, 58, 60, 59, 59, 53, 64, 61
};

static const char _json_trans_actions[] = {
	0, 0, 0, 65, 118, 68, 19, 98, 
	27, 21, 0, 0, 56, 23, 59, 102, 
	0, 25, 62, 19, 0, 53, 1, 1, 
	1, 0, 0, 3, 0, 0, 0, 0, 
	0, 5, 15, 0, 0, 41, 7, 13, 
	0, 44, 9, 9, 9, 47, 50, 11, 
	110, 106, 114, 37, 37, 37, 95, 35, 
	39, 77, 71, 29, 33, 31, 31, 74, 
	0, 0, 29, 17, 0, 92, 0, 0, 
	0, 0, 83, 0, 0, 0, 86, 0, 
	0, 0, 80, 65, 118, 68, 19, 98, 
	27, 21, 0, 0, 56, 23, 59, 102, 
	0, 25, 62, 19, 0, 53, 89, 0
};

static const int json_start = 1;

static const int json_en_number_machine = 11;
static const int json_en_string_machine = 20;
static const int json_en_value_machine = 28;
static const int json_en_main = 1;


#line 358 "upb/json/parser.rl"

size_t parse_json(void *closure, const void *hd, const char *buf, size_t size,
                  const upb_bufhandle *handle) {
  UPB_UNUSED(hd);
  UPB_UNUSED(handle);
  upb_json_parser *parser = closure;
  parser->handle = handle;

  // Variables used by Ragel's generated code.
  int cs = parser->current_state;
  int *stack = parser->parser_stack;
  int top = parser->parser_top;

  const char *p = buf;
  const char *pe = buf + size;

  if (parser->u.string_bytes < 0) {
    parser->u.text_start = NULL;
  } else if (parser->u.string_bytes == 0) {
    start_text(parser, p);
  } else {
    // XXX: This isn't quite right yet.
    start_text(parser, p);
    p += parser->u.string_bytes;
    if (!end_text(parser, p, handle)) goto error;
  }

  
#line 421 "upb/json/parser.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_keys = _json_trans_keys + _json_key_offsets[cs];
	_trans = _json_index_offsets[cs];

	_klen = _json_single_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _json_range_lengths[cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _json_indicies[_trans];
	cs = _json_trans_targs[_trans];

	if ( _json_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _json_actions + _json_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 230 "upb/json/parser.rl"
	{ start_text(parser, p); }
	break;
	case 1:
#line 232 "upb/json/parser.rl"
	{ p--; TRY(end_text(parser, p, handle)); {cs = stack[--top]; goto _again;} }
	break;
	case 2:
#line 233 "upb/json/parser.rl"
	{ p--; {stack[top++] = cs; cs = 11; goto _again;} }
	break;
	case 3:
#line 237 "upb/json/parser.rl"
	{ start_text(parser, p); }
	break;
	case 4:
#line 238 "upb/json/parser.rl"
	{ TRY(end_text(parser, p, handle)); }
	break;
	case 5:
#line 244 "upb/json/parser.rl"
	{ start_hex(parser); }
	break;
	case 6:
#line 245 "upb/json/parser.rl"
	{ hexdigit(parser, p); }
	break;
	case 7:
#line 246 "upb/json/parser.rl"
	{ TRY(end_hex(parser)); }
	break;
	case 8:
#line 252 "upb/json/parser.rl"
	{ TRY(escape(parser, p)); }
	break;
	case 9:
#line 258 "upb/json/parser.rl"
	{ p--; {cs = stack[--top]; goto _again;} }
	break;
	case 10:
#line 261 "upb/json/parser.rl"
	{ {stack[top++] = cs; cs = 20; goto _again;} }
	break;
	case 11:
#line 263 "upb/json/parser.rl"
	{ p--; {stack[top++] = cs; cs = 28; goto _again;} }
	break;
	case 12:
#line 267 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startsubmsg(
             sink, S(JSONOBJECT_PROPERTIES_STARTSUBMSG), subsink));
         TRY(upb_sink_startmsg(sink)); }
	break;
	case 13:
#line 271 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startstr(
             sink, S(JSONOBJECT_PROPERTIESENTRY_KEY_STARTSTR),
             UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONOBJECT_PROPERTIESENTRY_KEY_STRING); }
	break;
	case 14:
#line 275 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endstr(
             sink, S(JSONOBJECT_PROPERTIESENTRY_KEY_ENDSTR))); }
	break;
	case 15:
#line 279 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startsubmsg(
             sink, S(JSONOBJECT_PROPERTIESENTRY_VALUE_STARTSUBMSG), subsink)); }
	break;
	case 16:
#line 281 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endsubmsg(
             sink, S(JSONOBJECT_PROPERTIESENTRY_VALUE_ENDSUBMSG))); }
	break;
	case 17:
#line 284 "upb/json/parser.rl"
	{ TRY(upb_sink_endmsg(sink, NULL));
         TRY_POP(upb_sink_endsubmsg(sink, S(JSONOBJECT_PROPERTIES_ENDSUBMSG)));
       }
	break;
	case 18:
#line 292 "upb/json/parser.rl"
	{ TRY(upb_sink_startmsg(sink)); }
	break;
	case 19:
#line 295 "upb/json/parser.rl"
	{ TRY(upb_sink_endmsg(sink, NULL)); }
	break;
	case 20:
#line 300 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONARRAY_VALUE_STARTSUBMSG),
                                       subsink)); }
	break;
	case 21:
#line 303 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONARRAY_VALUE_ENDSUBMSG))); }
	break;
	case 22:
#line 308 "upb/json/parser.rl"
	{ TRY(upb_sink_startmsg(sink));
         TRY_PUSH(upb_sink_startseq(sink, S(JSONARRAY_VALUE_STARTSEQ),
                                    subsink));
       }
	break;
	case 23:
#line 315 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endseq(sink, S(JSONARRAY_VALUE_ENDSEQ)));
         TRY(upb_sink_endmsg(sink, NULL)); }
	break;
	case 24:
#line 321 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startstr(sink, S(JSONVALUE_NUMBER_VALUE_STARTSTR),
                                    UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONVALUE_NUMBER_VALUE_STRING);
       }
	break;
	case 25:
#line 325 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endstr(sink, S(JSONVALUE_NUMBER_VALUE_ENDSTR))); }
	break;
	case 26:
#line 327 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startstr(sink, S(JSONVALUE_STRING_VALUE_STARTSTR),
                                    UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONVALUE_STRING_VALUE_STRING);
       }
	break;
	case 27:
#line 331 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endstr(sink, S(JSONVALUE_STRING_VALUE_ENDSTR))); }
	break;
	case 28:
#line 333 "upb/json/parser.rl"
	{ TRY(upb_sink_putbool(sink, S(JSONVALUE_BOOLEAN_VALUE_BOOL), true)); }
	break;
	case 29:
#line 335 "upb/json/parser.rl"
	{ TRY(upb_sink_putbool(sink, S(JSONVALUE_BOOLEAN_VALUE_BOOL), false)); }
	break;
	case 30:
#line 337 "upb/json/parser.rl"
	{ TRY(upb_sink_putbool(sink, S(JSONVALUE_IS_NULL_BOOL), true)); }
	break;
	case 31:
#line 339 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONVALUE_OBJECT_VALUE_STARTSUBMSG),
                                       subsink)); }
	break;
	case 32:
#line 341 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONVALUE_OBJECT_VALUE_ENDSUBMSG))); }
	break;
	case 33:
#line 343 "upb/json/parser.rl"
	{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONVALUE_ARRAY_VALUE_STARTSUBMSG),
                                       subsink)); }
	break;
	case 34:
#line 345 "upb/json/parser.rl"
	{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONVALUE_ARRAY_VALUE_ENDSUBMSG))); }
	break;
	case 35:
#line 350 "upb/json/parser.rl"
	{ TRY(upb_sink_startmsg(sink)); }
	break;
	case 36:
#line 352 "upb/json/parser.rl"
	{ p--; TRY(upb_sink_endmsg(sink, NULL)); {cs = stack[--top]; goto _again;} }
	break;
#line 666 "upb/json/parser.c"
		}
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}

#line 386 "upb/json/parser.rl"

  if (p != pe) {
    upb_status status = UPB_STATUS_INIT;
    upb_status_seterrf(&status, "Parse error at %s\n", p);
    upb_env_reporterror(parser->env, &status);
  } else {
    if (parser->u.text_start) {
      if (end_text(parser, p, handle)) {
        parser->u.string_bytes = 0;
      } else {
        parser->u.string_bytes = p - parser->u.text_start;
        p = parser->u.text_start;
      }
    } else {
      parser->u.string_bytes = -1;
    }
  }

error:
  // Save parsing state back to parser.
  parser->current_state = cs;
  parser->parser_top = top;

  return p - buf;
}

#undef TRY
#undef TRY_PUSH
#undef TRY_POP
#undef S

bool end_json(void *closure, const void *hd) {
  UPB_UNUSED(closure);
  UPB_UNUSED(hd);

  // Prevent compile warning on unused static constants.
  UPB_UNUSED(json_start);
  UPB_UNUSED(json_en_number_machine);
  UPB_UNUSED(json_en_string_machine);
  UPB_UNUSED(json_en_value_machine);
  UPB_UNUSED(json_en_main);
  return true;
}

static void json_parser_reset(upb_json_parser *p) {
  p->top = p->stack;

  int cs;
  int top;
  // Emit Ragel initialization of the parser.
  
#line 731 "upb/json/parser.c"
	{
	cs = json_start;
	top = 0;
	}

#line 437 "upb/json/parser.rl"
  p->current_state = cs;
  p->parser_top = top;
  p->u.string_bytes = -1;
}


/* Public API *****************************************************************/

upb_json_parser *upb_json_parser_create(upb_env *env, upb_sink *output) {
#ifndef NDEBUG
  const size_t size_before = upb_env_bytesallocated(env);
#endif
  upb_json_parser *p = upb_env_malloc(env, sizeof(upb_json_parser));
  if (!p) return false;

  p->env = env;
  p->limit = p->stack + UPB_JSON_MAX_DEPTH;
  upb_byteshandler_init(&p->input_handler_);
  upb_byteshandler_setstring(&p->input_handler_, parse_json, NULL);
  upb_byteshandler_setendstr(&p->input_handler_, end_json, NULL);
  upb_bytessink_reset(&p->input_, &p->input_handler_, p);

  json_parser_reset(p);
  upb_sink_reset(p->top, output->handlers, output->closure);

  // If this fails, uncomment and increase the value in parser.h.
  // fprintf(stderr, "%zd\n", upb_env_bytesallocated(env) - size_before);
  assert(upb_env_bytesallocated(env) - size_before <= UPB_JSON_PARSER_SIZE);
  return p;
}

upb_bytessink *upb_json_parser_input(upb_json_parser *p) {
  return &p->input_;
}
