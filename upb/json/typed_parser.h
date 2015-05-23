/*
 * upb - a minimalist implementation of protocol buffers.
 *
 * Copyright (c) 2014 Google Inc.  See LICENSE for details.
 * Author: Josh Haberman <jhaberman@gmail.com>
 *
 * upb::json::TypedParser can parse JSON according to a specific schema.
 * For parsing generic JSON, use upb::json::Parser instead.
 *
 * Note: this class parses textual JSON.  If we ever had a situation where
 * we had data with JSON semantics, but that used a different wire encoding
 * of it (like ubjson: http://ubjson.org/) and wanted to convert it to
 * schema'd data using the same code/rules, we would need to add a different
 * json.proto -> arbitrary.proto converter.  It would likely share a lot of
 * code with TypedParser.
 */

#ifndef UPB_JSON_PARSER_H_
#define UPB_JSON_PARSER_H_

#include "upb/env.h"
#include "upb/sink.h"

#ifdef __cplusplus
namespace upb {
namespace json {
class TypedParser;
}  // namespace json
}  // namespace upb
#endif

UPB_DECLARE_TYPE(upb::json::TypedParser, upb_json_typedparser);

/* upb::json::TypedParser *****************************************************/

// Preallocation hint: parser won't allocate more bytes than this when first
// constructed.  This hint may be an overestimate for some build configurations.
// But if the parser library is upgraded without recompiling the application,
// it may be an underestimate.
#define UPB_JSON_TYPEDPARSER_SIZE 3568

#ifdef __cplusplus

// Parses an incoming BytesStream, pushing the results to the destination sink.
class upb::json::TypedParser {
 public:
  static Parser* Create(Environment* env, Sink* output);

  BytesSink* input();

 private:
  UPB_DISALLOW_POD_OPS(Parser, upb::json::TypedParser);
};

#endif

UPB_BEGIN_EXTERN_C

upb_json_typedparser *upb_json_typedparser_create(upb_env *e, upb_sink *output);
upb_bytessink *upb_json_typedparser_input(upb_json_parser *p);

UPB_END_EXTERN_C

#ifdef __cplusplus

namespace upb {
namespace json {
inline Parser* TypedParser::Create(Environment* env, Sink* output) {
  return upb_json_typedparser_create(env, output);
}
inline BytesSink* Parser::input() {
  return upb_json_typedparser_input(this);
}
}  // namespace json
}  // namespace upb

#endif

#endif  // UPB_JSON_TYPEDPARSER_H_
