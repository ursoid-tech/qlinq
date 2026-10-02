#ifndef QLINQ_TUN_JSON_H
#define QLINQ_TUN_JSON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* small bounded JSON reader for local profiles and control messages. no
 * allocation is based on an untrusted length; duplicate keys are rejected. */
#define TJ_MAX_BYTES 65536
#define TJ_MAX_NODES 512
typedef enum { TJ_OBJECT, TJ_ARRAY, TJ_STRING, TJ_NUMBER, TJ_LITERAL } tj_type;
typedef struct {
  tj_type type;
  int child, next;
  unsigned start, end;
  char *text;
} tj_node;
typedef struct {
  char input[TJ_MAX_BYTES + 1];
  char strings[TJ_MAX_BYTES + 1];
  tj_node nodes[TJ_MAX_NODES];
  unsigned pos, used, count;
} tj_doc;

bool tj_parse(tj_doc *doc, const char *text);
bool tj_load(tj_doc *doc, const char *path);
const tj_node *tj_get(const tj_doc *doc, const tj_node *object,
                      const char *key);
const char *tj_string(const tj_doc *doc, const tj_node *object,
                      const char *key);
bool tj_u64(const tj_node *node, uint64_t *value);
void tj_quote(FILE *out, const char *text);

#endif
