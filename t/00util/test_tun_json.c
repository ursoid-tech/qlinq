#include "../../src/host/linux/tun_json.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
  tj_doc *d = malloc(sizeof(*d));
  assert(d);
  const char *valid[] = {"{}",
                         "[]",
                         "[true,false,null,0,-1,1.2,1e+3]",
                         "{\"a\":{\"a\":1},\"b\":[{\"a\":2}]}",
                         "\"\\uD83D\\uDE00\"",
                         "\"\\b\\f\\n\\r\\t\\/\\\\\\\"\""};
  const char *invalid[] = {"",
                           "{",
                           "[",
                           "[1,]",
                           "{\"a\":1,}",
                           "{\"a\":1,\"a\":2}",
                           "{\"a\":1,\"\\u0061\":2}",
                           "[01]",
                           "[1.]",
                           "[1e]",
                           "[+1]",
                           "[NaN]",
                           "[nul]",
                           "true false",
                           "\"\\q\"",
                           "\"\\u0000\"",
                           "\"\\ud800\"",
                           "\"\\udc00\"",
                           "\"raw\nnewline\""};
  for (unsigned i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
    assert(tj_parse(d, valid[i]));
  for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++)
    assert(!tj_parse(d, invalid[i]));
  assert(tj_parse(
      d, "{\"state\":\"li\\u0073ten\",\"count\":18446744073709551615}"));
  assert(!strcmp(tj_string(d, &d->nodes[0], "state"), "listen"));
  uint64_t v;
  assert(tj_u64(tj_get(d, &d->nodes[0], "count"), &v) && v == UINT64_MAX);
  assert(tj_parse(d, "18446744073709551616") && !tj_u64(&d->nodes[0], &v));
  char *text = malloc(TJ_MAX_BYTES + 2);
  assert(text);
  memset(text, 'x', TJ_MAX_BYTES + 1);
  text[TJ_MAX_BYTES + 1] = 0;
  assert(!tj_parse(d, text));
  text[0] = '"';
  text[TJ_MAX_BYTES - 1] = '"';
  text[TJ_MAX_BYTES] = 0;
  assert(tj_parse(d, text));
  for (unsigned i = 1; i <= TJ_MAX_BYTES; i += 251) {
    char saved = text[i];
    text[i] = 0;
    if (i < TJ_MAX_BYTES)
      assert(!tj_parse(d, text));
    text[i] = saved;
  }
  /* deterministic malformed-input smoke fuzzing, also run under sanitizers */
  uint32_t random = 17;
  const char alphabet[] = "{}[]\"\\,:0123456789truefalsn \r\n\t";
  for (unsigned i = 0; i < 20000; i++) {
    unsigned length = i % 257;
    for (unsigned j = 0; j < length; j++) {
      random = random * 1664525U + 1013904223U;
      text[j] = alphabet[random % (sizeof(alphabet) - 1)];
    }
    text[length] = 0;
    (void)tj_parse(d, text);
  }
  free(text);
  free(d);
  puts("=== TUN JSON OK ===");
  return 0;
}
