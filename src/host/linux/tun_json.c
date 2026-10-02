#include "tun_json.h"
#include "cli_parse.h"
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void space(tj_doc *d) {
  while (d->input[d->pos] && strchr(" \t\r\n", d->input[d->pos]))
    d->pos++;
}

static bool hex4(tj_doc *d, unsigned *value) {
  *value = 0;
  for (int i = 0; i < 4; i++) {
    unsigned char c = d->input[d->pos];
    if (!isxdigit(c))
      return false;
    d->pos++;
    *value = *value * 16 + (isdigit(c) ? c - '0' : tolower(c) - 'a' + 10);
  }
  return true;
}

static bool string(tj_doc *d, tj_node *n) {
  n->text = d->strings + d->used;
  d->pos++;
  while (d->input[d->pos] != '"') {
    unsigned char c = d->input[d->pos++];
    if (c < 32)
      return false;
    if (c == '\\') {
      c = d->input[d->pos++];
      const char *esc = strchr("\"\\/bfnrt", c);
      if (!c)
        return false;
      if (esc) {
        c = "\"\\/\b\f\n\r\t"[esc - "\"\\/bfnrt"];
      } else if (c == 'u') {
        unsigned code;
        if (!hex4(d, &code) || code == 0)
          return false; /* embedded NUL is not representable in C fields */
        if (code >= 0xd800 && code <= 0xdbff) {
          unsigned low;
          if (d->input[d->pos] != '\\' || d->input[d->pos + 1] != 'u')
            return false;
          d->pos += 2;
          if (!hex4(d, &low) || low < 0xdc00 || low > 0xdfff)
            return false;
          code = 0x10000 + ((code - 0xd800) << 10) + low - 0xdc00;
        } else if (code >= 0xdc00 && code <= 0xdfff) {
          return false;
        }
        if (d->used + 4 >= sizeof(d->strings))
          return false;
        if (code >= 0x10000) {
          d->strings[d->used++] = 0xf0 | (code >> 18);
          d->strings[d->used++] = 0x80 | ((code >> 12) & 63);
          d->strings[d->used++] = 0x80 | ((code >> 6) & 63);
          c = 0x80 | (code & 63);
        } else if (code >= 0x800) {
          d->strings[d->used++] = 0xe0 | (code >> 12);
          d->strings[d->used++] = 0x80 | ((code >> 6) & 63);
          c = 0x80 | (code & 63);
        } else if (code >= 0x80) {
          d->strings[d->used++] = 0xc0 | (code >> 6);
          c = 0x80 | (code & 63);
        } else {
          c = code;
        }
      } else {
        return false;
      }
    }
    if (d->used >= sizeof(d->strings))
      return false;
    d->strings[d->used++] = c;
  }
  d->pos++;
  if (d->used >= sizeof(d->strings))
    return false;
  d->strings[d->used++] = 0;
  return true;
}

static int value(tj_doc *d, unsigned depth) {
  space(d);
  if (depth > 16 || d->count == TJ_MAX_NODES)
    return -1;
  int index = d->count++;
  tj_node *n = &d->nodes[index];
  *n = (tj_node){.child = -1, .next = -1, .start = d->pos};
  char c = d->input[d->pos];
  if (c == '{' || c == '[') {
    n->type = c == '{' ? TJ_OBJECT : TJ_ARRAY;
    char close = c == '{' ? '}' : ']';
    d->pos++;
    space(d);
    int *link = &n->child;
    if (d->input[d->pos] != close) {
      for (;;) {
        int child = value(d, depth + 1);
        if (child < 0)
          return -1;
        if (n->type == TJ_OBJECT) {
          if (d->nodes[child].type != TJ_STRING)
            return -1;
          for (int p = n->child; p >= 0; p = d->nodes[d->nodes[p].next].next)
            if (strcmp(d->nodes[p].text, d->nodes[child].text) == 0)
              return -1;
        }
        *link = child;
        link = &d->nodes[child].next;
        if (n->type == TJ_OBJECT) {
          space(d);
          if (d->input[d->pos++] != ':')
            return -1;
          child = value(d, depth + 1);
          if (child < 0)
            return -1;
          *link = child;
          link = &d->nodes[child].next;
        }
        space(d);
        if (d->input[d->pos] == close)
          break;
        if (d->input[d->pos++] != ',')
          return -1;
      }
    }
    d->pos++;
  } else if (c == '"') {
    n->type = TJ_STRING;
    if (!string(d, n))
      return -1;
  } else {
    n->text = d->strings + d->used;
    if (c == '-' || isdigit((unsigned char)c)) {
      n->type = TJ_NUMBER;
      if (c == '-')
        d->pos++;
      if (d->input[d->pos] == '0')
        d->pos++;
      else {
        if (d->input[d->pos] < '1' || d->input[d->pos] > '9')
          return -1;
        while (isdigit((unsigned char)d->input[d->pos]))
          d->pos++;
      }
      if (d->input[d->pos] == '.') {
        d->pos++;
        if (!isdigit((unsigned char)d->input[d->pos]))
          return -1;
        while (isdigit((unsigned char)d->input[d->pos]))
          d->pos++;
      }
      if (d->input[d->pos] == 'e' || d->input[d->pos] == 'E') {
        d->pos++;
        if (d->input[d->pos] == '+' || d->input[d->pos] == '-')
          d->pos++;
        if (!isdigit((unsigned char)d->input[d->pos]))
          return -1;
        while (isdigit((unsigned char)d->input[d->pos]))
          d->pos++;
      }
    } else {
      n->type = TJ_LITERAL;
      const char *literal = c == 't' ? "true" : c == 'f' ? "false" : "null";
      if (strncmp(d->input + d->pos, literal, strlen(literal)) != 0)
        return -1;
      d->pos += strlen(literal);
    }
    size_t length = d->pos - n->start;
    if (d->used + length + 1 > sizeof(d->strings))
      return -1;
    memcpy(d->strings + d->used, d->input + n->start, length);
    d->used += length;
    d->strings[d->used++] = 0;
  }
  n->end = d->pos;
  return index;
}

bool tj_parse(tj_doc *d, const char *text) {
  size_t length = strnlen(text, TJ_MAX_BYTES + 1);
  if (length > TJ_MAX_BYTES)
    return false;
  memmove(d->input, text, length + 1);
  d->pos = d->count = d->used = 0;
  if (value(d, 0) != 0)
    return false;
  space(d);
  return d->input[d->pos] == 0;
}

bool tj_load(tj_doc *d, const char *path) {
  int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  struct stat st;
  if (fd < 0)
    return false;
  bool ok =
      fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size <= TJ_MAX_BYTES;
  size_t size = 0;
  while (ok && size <= TJ_MAX_BYTES) {
    ssize_t n = read(fd, d->input + size, TJ_MAX_BYTES + 1 - size);
    if (n < 0) {
      ok = false;
      break;
    }
    if (n == 0)
      break;
    size += n;
  }
  close(fd);
  if (!ok || size > TJ_MAX_BYTES || memchr(d->input, 0, size))
    return false;
  d->input[size] = 0;
  return tj_parse(d, d->input);
}

const tj_node *tj_get(const tj_doc *d, const tj_node *obj, const char *key) {
  if (!obj || obj->type != TJ_OBJECT)
    return NULL;
  for (int i = obj->child; i >= 0; i = d->nodes[d->nodes[i].next].next)
    if (strcmp(d->nodes[i].text, key) == 0)
      return &d->nodes[d->nodes[i].next];
  return NULL;
}

const char *tj_string(const tj_doc *d, const tj_node *obj, const char *key) {
  const tj_node *n = tj_get(d, obj, key);
  return n && n->type == TJ_STRING ? n->text : NULL;
}

bool tj_u64(const tj_node *n, uint64_t *v) {
  return n && n->type == TJ_NUMBER && cli_parse_u64(n->text, UINT64_MAX, v);
}

void tj_quote(FILE *out, const char *s) {
  fputc('"', out);
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (*p < 32 || *p == '"' || *p == '\\')
      fprintf(out, "\\u%04x", *p);
    else
      fputc(*p, out);
  }
  fputc('"', out);
}
