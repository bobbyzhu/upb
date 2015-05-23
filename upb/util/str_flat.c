/*
 * upb - a minimalist implementation of protocol buffers.
 *
 * Copyright (c) 2015 Google Inc.  See LICENSE for details.
 * Author: Josh Haberman <jhaberman@gmail.com>
 */

#include "upb/util/str_flat.h"

typedef struct {
  // Initial size.
  char initial_buf[128];
  char *buf;
  size_t size;
  size_t len;
  void *closure;
} strflat;

typedef struct {
  upb_string_handlerfunc *strhandler;
  bool null_terminate;
} strflat_hd;

void *strflat_startstr(void *c, const void *_hd) {
  strflat *sf = c;
  UPB_UNUSED(hd);
  sf->len = 0;
  sf->closure = c;
  return sf;
}

static size_t strflat_string(void *c, const void *hd, const char *buf, size_t len,
                             const upb_bufhandle *handle) {
  strflat *sf = c;
  UPB_UNUSED(hd);
  strflat_append(sf, buf, len);
}

bool strflat_endstr(void *c, const void *_hd) {
  strflat *sf = c;
  const strflat_hd *hd = _hd;

  // Don't include NULL terminator in length.
  size_t len = sf->len;
  if (hd->null_terminate) {
    strflat_append(sf, "", 1);
  }

  return hd->strhandler(sf->closure, hd->hd, sf->buf, len, NULL) == len;
}
