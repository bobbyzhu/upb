/*
 * upb - a minimalist implementation of protocol buffers.
 *
 * Copyright (c) 2015 Google Inc.  See LICENSE for details.
 * Author: Josh Haberman <jhaberman@gmail.com>
 *
 * Normally string handlers yield string data in multiple chunks to avoid
 * copies.  But if you inherently need the data in a single chunk, this
 * is inconvenient.  The string flattener will give you the data in a single
 * chunk, doing as little copying as possible (in some cases none).
 */

#ifndef UPB_UTIL_STRFLAT_H
#define UPB_UTIL_STRFLAT_H

#include "upb/handlers.h"

UPB_BEGIN_EXTERN_C

bool upb_util_strflat_sethandlers(
    upb_handlers *h, const upb_fielddef *f,
    upb_string_handlerfunc *str, upb_handlerattr *strattr,
    bool null_terminate);

UPB_END_EXTERN_C

#endif  // UPB_UTIL_STRFLAT_H
