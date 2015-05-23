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

%%{
  machine json;

  ws = space*;

  integer  = "0" | /[1-9]/ /[0-9]/*;
  decimal  = "." /[0-9]/+;
  exponent = /[eE]/ /[+\-]/? /[0-9]/+;

  number_parts = ("-"? integer decimal? exponent?);

  number_machine :=
    number_parts
      >{ start_text(parser, p); }
    <: any
      >{ fhold; TRY(end_text(parser, p, handle)); fret; };
  number  = /[0-9\-]/ >{ fhold; fcall number_machine; };

  text =
    /[^\\"]/+
      >{ start_text(parser, p); }
      %{ TRY(end_text(parser, p, handle)); }
    ;

  unicode_char =
    "\\u"
    /[0-9A-Fa-f]/{4}
      >{ start_hex(parser); }
      ${ hexdigit(parser, p); }
      %{ TRY(end_hex(parser)); }
    ;

  escape_char  =
    "\\"
    /[rtbfn"\/\\]/
      >{ TRY(escape(parser, p)); }
    ;

  string_machine :=
    (text | unicode_char | escape_char)**
    '"'
      @{ fhold; fret; }
    ;

  string       = '"' @{ fcall string_machine; } '"';

  value2 = ^(space | "]" | "}") >{ fhold; fcall value_machine; } ;

  member =
    ws
      >{ TRY_PUSH(upb_sink_startsubmsg(
             sink, S(JSONOBJECT_PROPERTIES_STARTSUBMSG), subsink));
         TRY(upb_sink_startmsg(sink)); }
    string
      >{ TRY_PUSH(upb_sink_startstr(
             sink, S(JSONOBJECT_PROPERTIESENTRY_KEY_STARTSTR),
             UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONOBJECT_PROPERTIESENTRY_KEY_STRING); }
      @{ TRY_POP(upb_sink_endstr(
             sink, S(JSONOBJECT_PROPERTIESENTRY_KEY_ENDSTR))); }
    ws ":" ws
    value2
      >{ TRY_PUSH(upb_sink_startsubmsg(
             sink, S(JSONOBJECT_PROPERTIESENTRY_VALUE_STARTSUBMSG), subsink)); }
      %{ TRY_POP(upb_sink_endsubmsg(
             sink, S(JSONOBJECT_PROPERTIESENTRY_VALUE_ENDSUBMSG))); }
    ws
      %{ TRY(upb_sink_endmsg(sink, NULL));
         TRY_POP(upb_sink_endsubmsg(sink, S(JSONOBJECT_PROPERTIES_ENDSUBMSG)));
       }
    ;

  object =
    "{"
    ws
      >{ TRY(upb_sink_startmsg(sink)); }
    (member ("," member)*)?
    "}"
      >{ TRY(upb_sink_endmsg(sink, NULL)); }
    ;

  element =
    ws
      >{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONARRAY_VALUE_STARTSUBMSG),
                                       subsink)); }
    value2
      %{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONARRAY_VALUE_ENDSUBMSG))); }
    ws;

  array   =
    "["
      >{ TRY(upb_sink_startmsg(sink));
         TRY_PUSH(upb_sink_startseq(sink, S(JSONARRAY_VALUE_STARTSEQ),
                                    subsink));
       }
    ws
    (element ("," element)*)?
    "]"
      >{ TRY_POP(upb_sink_endseq(sink, S(JSONARRAY_VALUE_ENDSEQ)));
         TRY(upb_sink_endmsg(sink, NULL)); }
    ;

  value =
    number
      >{ TRY_PUSH(upb_sink_startstr(sink, S(JSONVALUE_NUMBER_VALUE_STARTSTR),
                                    UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONVALUE_NUMBER_VALUE_STRING);
       }
      %{ TRY_POP(upb_sink_endstr(sink, S(JSONVALUE_NUMBER_VALUE_ENDSTR))); }
    | string
      >{ TRY_PUSH(upb_sink_startstr(sink, S(JSONVALUE_STRING_VALUE_STARTSTR),
                                    UPB_SIZE_UNKNOWN, subsink));
         parser->string_selector = S(JSONVALUE_STRING_VALUE_STRING);
       }
      @{ TRY_POP(upb_sink_endstr(sink, S(JSONVALUE_STRING_VALUE_ENDSTR))); }
    | "true"
      %{ TRY(upb_sink_putbool(sink, S(JSONVALUE_BOOLEAN_VALUE_BOOL), true)); }
    | "false"
      %{ TRY(upb_sink_putbool(sink, S(JSONVALUE_BOOLEAN_VALUE_BOOL), false)); }
    | "null"
      %{ TRY(upb_sink_putbool(sink, S(JSONVALUE_IS_NULL_BOOL), true)); }
    | object
      >{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONVALUE_OBJECT_VALUE_STARTSUBMSG),
                                       subsink)); }
      %{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONVALUE_OBJECT_VALUE_ENDSUBMSG))); }
    | array
      >{ TRY_PUSH(upb_sink_startsubmsg(sink, S(JSONVALUE_ARRAY_VALUE_STARTSUBMSG),
                                       subsink)); }
      %{ TRY_POP(upb_sink_endsubmsg(sink, S(JSONVALUE_ARRAY_VALUE_ENDSUBMSG))); }
    ;

  value_machine :=
    value
      >{ TRY(upb_sink_startmsg(sink)); }
    <: any
      >{ fhold; TRY(upb_sink_endmsg(sink, NULL)); fret; } ;

  main := ws object ws;
}%%

%% write data noerror nofinal;

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

  %% write exec;

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
  %% write init;
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
