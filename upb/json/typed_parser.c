
typedef struct {
  upb_sink sink;

  // The current message in which we're parsing, and the field whose value we're
  // expecting next.
  const upb_msgdef *m;
  const upb_fielddef *f;

  // We are in a repeated-field context, ready to emit mapentries as
  // submessages. This flag alters the start-of-object (open-brace) behavior to
  // begin a sequence of mapentry messages rather than a single submessage.
  bool is_map;

  // We are in a map-entry message context. This flag is set when parsing the
  // value field of a single map entry and indicates to all value-field parsers
  // (subobjects, strings, numbers, and bools) that the map-entry submessage
  // should end as soon as the value is parsed.
  bool is_mapentry;

  // If |is_map| or |is_mapentry| is true, |mapfield| refers to the parent
  // message's map field that we're currently parsing. This differs from |f|
  // because |f| is the field in the *current* message (i.e., the map-entry
  // message itself), not the parent's field that leads to this map.
  const upb_fielddef *mapfield;
} upb_json_typedparser_frame;

struct upb_json_parser {
  upb_env *env;

  // Stack to track the JSON scopes we are in.
  upb_jsonparser_frame stack[UPB_JSON_MAX_DEPTH];
  upb_jsonparser_frame *top;
  upb_jsonparser_frame *limit;

  // The handle for the current buffer.
  const upb_bufhandle *handle;

  // Accumulate buffer.  See details below.
  const char *accumulated;
  size_t accumulated_len;
  char *accumulate_buf;
  size_t accumulate_buf_size;

  // Multi-part text data.  See details below.
  int multipart_state;
  upb_selector_t string_selector;

  // Input capture.  See details below.
  const char *capture;
};

#define PARSER_CHECK_RETURN(x) if (!(x)) return false

static upb_selector_t getsel_for_handlertype(upb_json_parser *p,
                                             upb_handlertype_t type) {
  upb_selector_t sel;
  bool ok = upb_handlers_getselector(p->top->f, type, &sel);
  UPB_ASSERT_VAR(ok, ok);
  return sel;
}

static upb_selector_t parser_getsel(upb_json_parser *p) {
  return getsel_for_handlertype(
      p, upb_handlers_getprimitivehandlertype(p->top->f));
}

static bool check_stack(upb_json_parser *p) {
  if ((p->top + 1) == p->limit) {
    upb_status_seterrmsg(p->status, "Nesting too deep");
    return false;
  }

  return true;
}

// There are GCC/Clang built-ins for overflow checking which we could start
// using if there was any performance benefit to it.

static bool checked_add(size_t a, size_t b, size_t *c) {
  if (SIZE_MAX - a < b) return false;
  *c = a + b;
  return true;
}

static size_t saturating_multiply(size_t a, size_t b) {
  // size_t is unsigned, so this is defined behavior even on overflow.
  size_t ret = a * b;
  if (b != 0 && ret / b != a) {
    ret = SIZE_MAX;
  }
  return ret;
}


/* Base64 decoding ************************************************************/

// TODO(haberman): make this streaming.

static const signed char b64table[] = {
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      62/*+*/, -1,      -1,      -1,      63/*/ */,
  52/*0*/, 53/*1*/, 54/*2*/, 55/*3*/, 56/*4*/, 57/*5*/, 58/*6*/, 59/*7*/,
  60/*8*/, 61/*9*/, -1,      -1,      -1,      -1,      -1,      -1,
  -1,       0/*A*/,  1/*B*/,  2/*C*/,  3/*D*/,  4/*E*/,  5/*F*/,  6/*G*/,
  07/*H*/,  8/*I*/,  9/*J*/, 10/*K*/, 11/*L*/, 12/*M*/, 13/*N*/, 14/*O*/,
  15/*P*/, 16/*Q*/, 17/*R*/, 18/*S*/, 19/*T*/, 20/*U*/, 21/*V*/, 22/*W*/,
  23/*X*/, 24/*Y*/, 25/*Z*/, -1,      -1,      -1,      -1,      -1,
  -1,      26/*a*/, 27/*b*/, 28/*c*/, 29/*d*/, 30/*e*/, 31/*f*/, 32/*g*/,
  33/*h*/, 34/*i*/, 35/*j*/, 36/*k*/, 37/*l*/, 38/*m*/, 39/*n*/, 40/*o*/,
  41/*p*/, 42/*q*/, 43/*r*/, 44/*s*/, 45/*t*/, 46/*u*/, 47/*v*/, 48/*w*/,
  49/*x*/, 50/*y*/, 51/*z*/, -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1,
  -1,      -1,      -1,      -1,      -1,      -1,      -1,      -1
};

// Returns the table value sign-extended to 32 bits.  Knowing that the upper
// bits will be 1 for unrecognized characters makes it easier to check for
// this error condition later (see below).
int32_t b64lookup(unsigned char ch) { return b64table[ch]; }

// Returns true if the given character is not a valid base64 character or
// padding.
bool nonbase64(unsigned char ch) { return b64lookup(ch) == -1 && ch != '='; }

static bool base64_push(upb_json_parser *p, upb_selector_t sel, const char *ptr,
                        size_t len) {
  const char *limit = ptr + len;
  for (; ptr < limit; ptr += 4) {
    if (limit - ptr < 4) {
      upb_status_seterrf(p->status,
                         "Base64 input for bytes field not a multiple of 4: %s",
                         upb_fielddef_name(p->top->f));
      return false;
    }

    uint32_t val = b64lookup(ptr[0]) << 18 |
                   b64lookup(ptr[1]) << 12 |
                   b64lookup(ptr[2]) << 6  |
                   b64lookup(ptr[3]);

    // Test the upper bit; returns true if any of the characters returned -1.
    if (val & 0x80000000) {
      goto otherchar;
    }

    char output[3];
    output[0] = val >> 16;
    output[1] = (val >> 8) & 0xff;
    output[2] = val & 0xff;
    upb_sink_putstring(&p->top->sink, sel, output, 3, NULL);
  }
  return true;

otherchar:
  if (nonbase64(ptr[0]) || nonbase64(ptr[1]) || nonbase64(ptr[2]) ||
      nonbase64(ptr[3]) ) {
    upb_status_seterrf(p->status,
                       "Non-base64 characters in bytes field: %s",
                       upb_fielddef_name(p->top->f));
    return false;
  } if (ptr[2] == '=') {
    // Last group contains only two input bytes, one output byte.
    if (ptr[0] == '=' || ptr[1] == '=' || ptr[3] != '=') {
      goto badpadding;
    }

    uint32_t val = b64lookup(ptr[0]) << 18 |
                   b64lookup(ptr[1]) << 12;

    assert(!(val & 0x80000000));
    char output = val >> 16;
    upb_sink_putstring(&p->top->sink, sel, &output, 1, NULL);
    return true;
  } else {
    // Last group contains only three input bytes, two output bytes.
    if (ptr[0] == '=' || ptr[1] == '=' || ptr[2] == '=') {
      goto badpadding;
    }

    uint32_t val = b64lookup(ptr[0]) << 18 |
                   b64lookup(ptr[1]) << 12 |
                   b64lookup(ptr[2]) << 6;

    char output[2];
    output[0] = val >> 16;
    output[1] = (val >> 8) & 0xff;
    upb_sink_putstring(&p->top->sink, sel, output, 2, NULL);
    return true;
  }

badpadding:
  upb_status_seterrf(p->status,
                     "Incorrect base64 padding for field: %s (%.*s)",
                     upb_fielddef_name(p->top->f),
                     4, ptr);
  return false;
}

static bool parse_number(upb_json_parser *p) {
  // strtol() and friends unfortunately do not support specifying the length of
  // the input string, so we need to force a copy into a NULL-terminated buffer.
  if (!multipart_text(p, "\0", 1, false)) {
    return false;
  }

  size_t len;
  const char *buf = accumulate_getptr(p, &len);
  const char *myend = buf + len - 1;  // One for NULL.

  char *end;
  switch (upb_fielddef_type(p->top->f)) {
    case UPB_TYPE_ENUM:
    case UPB_TYPE_INT32: {
      long val = strtol(p->accumulated, &end, 0);
      if (val > INT32_MAX || val < INT32_MIN || errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putint32(&p->top->sink, parser_getsel(p), val);
      break;
    }
    case UPB_TYPE_INT64: {
      long long val = strtoll(p->accumulated, &end, 0);
      if (val > INT64_MAX || val < INT64_MIN || errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putint64(&p->top->sink, parser_getsel(p), val);
      break;
    }
    case UPB_TYPE_UINT32: {
      unsigned long val = strtoul(p->accumulated, &end, 0);
      if (val > UINT32_MAX || errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putuint32(&p->top->sink, parser_getsel(p), val);
      break;
    }
    case UPB_TYPE_UINT64: {
      unsigned long long val = strtoull(p->accumulated, &end, 0);
      if (val > UINT64_MAX || errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putuint64(&p->top->sink, parser_getsel(p), val);
      break;
    }
    case UPB_TYPE_DOUBLE: {
      double val = strtod(p->accumulated, &end);
      if (errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putdouble(&p->top->sink, parser_getsel(p), val);
      break;
    }
    case UPB_TYPE_FLOAT: {
      float val = strtof(p->accumulated, &end);
      if (errno == ERANGE || end != myend)
        goto err;
      else
        upb_sink_putfloat(&p->top->sink, parser_getsel(p), val);
      break;
    }
    default:
      assert(false);
  }

  multipart_end(p);

  return true;

err:
  upb_status_seterrf(p->status, "error parsing number: %s", buf);
  multipart_end(p);
  return false;
}

static bool parser_putbool(upb_json_parser *p, bool val) {
  if (upb_fielddef_type(p->top->f) != UPB_TYPE_BOOL) {
    upb_status_seterrf(p->status,
                       "Boolean value specified for non-bool field: %s",
                       upb_fielddef_name(p->top->f));
    return false;
  }

  bool ok = upb_sink_putbool(&p->top->sink, parser_getsel(p), val);
  UPB_ASSERT_VAR(ok, ok);

  return true;
}

// Helper: invoked during parse_mapentry() to emit the mapentry message's key
// field based on the current contents of the accumulate buffer.
static bool parse_mapentry_key(upb_json_parser *p) {

  size_t len;
  const char *buf = accumulate_getptr(p, &len);

  // Emit the key field. We do a bit of ad-hoc parsing here because the
  // parser state machine has already decided that this is a string field
  // name, and we are reinterpreting it as some arbitrary key type. In
  // particular, integer and bool keys are quoted, so we need to parse the
  // quoted string contents here.

  p->top->f = upb_msgdef_itof(p->top->m, UPB_MAPENTRY_KEY);
  if (p->top->f == NULL) {
    upb_status_seterrmsg(p->status, "mapentry message has no key");
    return false;
  }
  switch (upb_fielddef_type(p->top->f)) {
    case UPB_TYPE_INT32:
    case UPB_TYPE_INT64:
    case UPB_TYPE_UINT32:
    case UPB_TYPE_UINT64:
      // Invoke end_number. The accum buffer has the number's text already.
      if (!parse_number(p)) {
        return false;
      }
      break;
    case UPB_TYPE_BOOL:
      if (len == 4 && !strncmp(buf, "true", 4)) {
        if (!parser_putbool(p, true)) {
          return false;
        }
      } else if (len == 5 && !strncmp(buf, "false", 5)) {
        if (!parser_putbool(p, false)) {
          return false;
        }
      } else {
        upb_status_seterrmsg(p->status,
                             "Map bool key not 'true' or 'false'");
        return false;
      }
      multipart_end(p);
      break;
    case UPB_TYPE_STRING:
    case UPB_TYPE_BYTES: {
      upb_sink subsink;
      upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
      upb_sink_startstr(&p->top->sink, sel, len, &subsink);
      sel = getsel_for_handlertype(p, UPB_HANDLER_STRING);
      upb_sink_putstring(&subsink, sel, buf, len, NULL);
      sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
      upb_sink_endstr(&subsink, sel);
      multipart_end(p);
      break;
    }
    default:
      upb_status_seterrmsg(p->status, "Invalid field type for map key");
      return false;
  }

  return true;
}

// Helper: emit one map entry (as a submessage in the map field sequence). This
// is invoked from end_membername(), at the end of the map entry's key string,
// with the map key in the accumulate buffer. It parses the key from that
// buffer, emits the handler calls to start the mapentry submessage (setting up
// its subframe in the process), and sets up state in the subframe so that the
// value parser (invoked next) will emit the mapentry's value field and then
// end the mapentry message.

static bool handle_mapentry(upb_json_parser *p) {
  // Map entry: p->top->sink is the seq frame, so we need to start a frame
  // for the mapentry itself, and then set |f| in that frame so that the map
  // value field is parsed, and also set a flag to end the frame after the
  // map-entry value is parsed.
  if (!check_stack(p)) return false;

  const upb_fielddef *mapfield = p->top->mapfield;
  const upb_msgdef *mapentrymsg = upb_fielddef_msgsubdef(mapfield);

  upb_jsonparser_frame *inner = p->top + 1;
  p->top->f = mapfield;
  upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSUBMSG);
  upb_sink_startsubmsg(&p->top->sink, sel, &inner->sink);
  inner->m = mapentrymsg;
  inner->mapfield = mapfield;
  inner->is_map = false;

  // Don't set this to true *yet* -- we reuse parsing handlers below to push
  // the key field value to the sink, and these handlers will pop the frame
  // if they see is_mapentry (when invoked by the parser state machine, they
  // would have just seen the map-entry value, not key).
  inner->is_mapentry = false;
  p->top = inner;

  // send STARTMSG in submsg frame.
  upb_sink_startmsg(&p->top->sink);

  parse_mapentry_key(p);

  // Set up the value field to receive the map-entry value.
  p->top->f = upb_msgdef_itof(p->top->m, UPB_MAPENTRY_VALUE);
  p->top->is_mapentry = true;  // set up to pop frame after value is parsed.
  p->top->mapfield = mapfield;
  if (p->top->f == NULL) {
    upb_status_seterrmsg(p->status, "mapentry message has no value");
    return false;
  }

  return true;
}


/* Handlers *******************************************************************/

static void start_text(upb_json_parser *p, const char *ptr) {
  capture_begin(p, ptr);
}

static bool end_text(upb_json_parser *p, const char *ptr) {
  return capture_end(p, ptr);
}

static void start_number(upb_json_parser *p, const char *ptr) {
  multipart_startaccum(p);
  capture_begin(p, ptr);
}

static bool end_number(upb_json_parser *p, const char *ptr) {
  if (!capture_end(p, ptr)) {
    return false;
  }

  return parse_number(p);
}

static bool start_stringval(upb_json_parser *p) {
  assert(p->top->f);

  if (upb_fielddef_isstring(p->top->f)) {
    if (!check_stack(p)) return false;

    // Start a new parser frame: parser frames correspond one-to-one with
    // handler frames, and string events occur in a sub-frame.
    upb_jsonparser_frame *inner = p->top + 1;
    upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSTR);
    upb_sink_startstr(&p->top->sink, sel, 0, &inner->sink);
    inner->m = p->top->m;
    inner->f = p->top->f;
    inner->is_map = false;
    inner->is_mapentry = false;
    p->top = inner;

    if (upb_fielddef_type(p->top->f) == UPB_TYPE_STRING) {
      // For STRING fields we push data directly to the handlers as it is
      // parsed.  We don't do this yet for BYTES fields, because our base64
      // decoder is not streaming.
      //
      // TODO(haberman): make base64 decoding streaming also.
      multipart_start(p, getsel_for_handlertype(p, UPB_HANDLER_STRING));
      return true;
    } else {
      multipart_startaccum(p);
      return true;
    }
  } else if (upb_fielddef_type(p->top->f) == UPB_TYPE_ENUM) {
    // No need to push a frame -- symbolic enum names in quotes remain in the
    // current parser frame.
    //
    // Enum string values must accumulate so we can look up the value in a table
    // once it is complete.
    multipart_startaccum(p);
    return true;
  } else {
    upb_status_seterrf(p->status,
                       "String specified for non-string/non-enum field: %s",
                       upb_fielddef_name(p->top->f));
    return false;
  }
}

static bool end_stringval(upb_json_parser *p) {
  bool ok = true;

  switch (upb_fielddef_type(p->top->f)) {
    case UPB_TYPE_BYTES:
      if (!base64_push(p, getsel_for_handlertype(p, UPB_HANDLER_STRING),
                       p->accumulated, p->accumulated_len)) {
        return false;
      }
      // Fall through.

    case UPB_TYPE_STRING: {
      upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSTR);
      upb_sink_endstr(&p->top->sink, sel);
      p->top--;
      break;
    }

    case UPB_TYPE_ENUM: {
      // Resolve enum symbolic name to integer value.
      const upb_enumdef *enumdef =
          (const upb_enumdef*)upb_fielddef_subdef(p->top->f);

      size_t len;
      const char *buf = accumulate_getptr(p, &len);

      int32_t int_val = 0;
      ok = upb_enumdef_ntoi(enumdef, buf, len, &int_val);

      if (ok) {
        upb_selector_t sel = parser_getsel(p);
        upb_sink_putint32(&p->top->sink, sel, int_val);
      } else {
        upb_status_seterrf(p->status, "Enum value unknown: '%.*s'", len, buf);
      }

      break;
    }

    default:
      assert(false);
      upb_status_seterrmsg(p->status, "Internal error in JSON decoder");
      ok = false;
      break;
  }

  multipart_end(p);

  return ok;
}

static void start_member(upb_json_parser *p) {
  assert(!p->top->f);
  multipart_startaccum(p);
}

static bool end_membername(upb_json_parser *p) {
  assert(!p->top->f);

  if (p->top->is_map) {
    return handle_mapentry(p);
  } else {
    size_t len;
    const char *buf = accumulate_getptr(p, &len);
    const upb_fielddef *f = upb_msgdef_ntof(p->top->m, buf, len);

    if (!f) {
      // TODO(haberman): Ignore unknown fields if requested/configured to do so.
      upb_status_seterrf(p->status, "No such field: %.*s\n", (int)len, buf);
      return false;
    }

    p->top->f = f;
    multipart_end(p);

    return true;
  }
}

static void end_member(upb_json_parser *p) {
  // If we just parsed a map-entry value, end that frame too.
  if (p->top->is_mapentry) {
    assert(p->top > p->stack);
    // send ENDMSG on submsg.
    upb_status s = UPB_STATUS_INIT;
    upb_sink_endmsg(&p->top->sink, &s);
    const upb_fielddef* mapfield = p->top->mapfield;

    // send ENDSUBMSG in repeated-field-of-mapentries frame.
    p->top--;
    upb_selector_t sel;
    bool ok = upb_handlers_getselector(mapfield,
                                       UPB_HANDLER_ENDSUBMSG, &sel);
    UPB_ASSERT_VAR(ok, ok);
    upb_sink_endsubmsg(&p->top->sink, sel);
  }

  p->top->f = NULL;
}

static bool start_subobject(upb_json_parser *p) {
  assert(p->top->f);

  if (upb_fielddef_ismap(p->top->f)) {
    // Beginning of a map. Start a new parser frame in a repeated-field
    // context.
    if (!check_stack(p)) return false;

    upb_jsonparser_frame *inner = p->top + 1;
    upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSEQ);
    upb_sink_startseq(&p->top->sink, sel, &inner->sink);
    inner->m = upb_fielddef_msgsubdef(p->top->f);
    inner->mapfield = p->top->f;
    inner->f = NULL;
    inner->is_map = true;
    inner->is_mapentry = false;
    p->top = inner;

    return true;
  } else if (upb_fielddef_issubmsg(p->top->f)) {
    // Beginning of a subobject. Start a new parser frame in the submsg
    // context.
    if (!check_stack(p)) return false;

    upb_jsonparser_frame *inner = p->top + 1;

    upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSUBMSG);
    upb_sink_startsubmsg(&p->top->sink, sel, &inner->sink);
    inner->m = upb_fielddef_msgsubdef(p->top->f);
    inner->f = NULL;
    inner->is_map = false;
    inner->is_mapentry = false;
    p->top = inner;

    return true;
  } else {
    upb_status_seterrf(p->status,
                       "Object specified for non-message/group field: %s",
                       upb_fielddef_name(p->top->f));
    return false;
  }
}

static void end_subobject(upb_json_parser *p) {
  if (p->top->is_map) {
    p->top--;
    upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSEQ);
    upb_sink_endseq(&p->top->sink, sel);
  } else {
    p->top--;
    upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSUBMSG);
    upb_sink_endsubmsg(&p->top->sink, sel);
  }
}

static void *array_startmsg(void *c, const void *hd) {
  UPB_UNUSED(hd);
  upb_json_typedparser *p = c;

  assert(p->top->f);

  if (!upb_fielddef_isseq(p->top->f)) {
    upb_status_seterrf(p->status,
                       "Array specified for non-repeated field: %s",
                       upb_fielddef_name(p->top->f));
    return false;
  }

  if (!check_stack(p)) return false;

  upb_jsonparser_frame *inner = p->top + 1;
  upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_STARTSEQ);
  upb_sink_startseq(&p->top->sink, sel, &inner->sink);
  inner->m = p->top->m;
  inner->f = p->top->f;
  inner->is_map = false;
  inner->is_mapentry = false;
  p->top = inner;

  return c;
}

static bool array_endmsg(void *c, const void *hd, upb_status *s) {
  UPB_UNUSED(hd);
  UPB_UNUSED(s);
  upb_json_typedparser *p = c;

  assert(p->top > p->stack);

  p->top--;
  upb_selector_t sel = getsel_for_handlertype(p, UPB_HANDLER_ENDSEQ);
  upb_sink_endseq(&p->top->sink, sel);
}

static void *object_startmsg(void *c, const void *hd) {
  UPB_UNUSED(hd);
  upb_json_typedparser *p = c;

  if (!p->top->is_map) {
    upb_sink_startmsg(&p->top->sink);
  }

  return c;
}

static bool object_endmsg(void *c, const void *hd, upb_status *s) {
  UPB_UNUSED(hd);
  UPB_UNUSED(s);
  upb_json_typedparser *p = c;

  if (!p->top->is_map) {
    upb_status status;
    upb_sink_endmsg(&p->top->sink, &status);
  }

  return true;
}


static void reghandlers(const void *closure, upb_handlers *h) {
  const upb_msgdef *m = upb_handlers_msgdef(h);

  if (m == D(JsonObject)) {
    upb_handlers_setstartmsg(h, &object_startmsg, NULL);
    upb_handlers_setendmsg(h, &object_endmsg, NULL);
  } else if (m == D(JsonArray)) {
    upb_handlers_setstartmsg(h, &array_startmsg, NULL);
    upb_handlers_setendmsg(h, &array_endmsg, NULL);
  } else if (m == D(JsonObject_PropertiesEntry)) {
    upb_handlers_setstartmsg(h, &enumval_startmsg, NULL);
    upb_handlers_setendmsg(h, &enumval_endmsg, NULL);
    upb_handlers_setstring(h, D(EnumValueDescriptorProto_name), &enumval_onname, NULL);
    upb_handlers_setint32(h, D(EnumValueDescriptorProto_number), &enumval_onnumber,
                          NULL);
  } else if (m == D(JsonValue)) {
    upb_handlers_setstartmsg(h, &enum_startmsg, NULL);
    upb_handlers_setendmsg(h, &enum_endmsg, NULL);
    upb_handlers_setstring(h, D(EnumDescriptorProto_name), &enum_onname, NULL);
  }
}
