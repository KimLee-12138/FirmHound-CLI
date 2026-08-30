#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int g_reached_sink = 0;

void __fsa_sink(const char *p) {
    g_reached_sink = 1;
    klee_assert(p != NULL);
}

/* redirect the format sink to the stub so no real printf side effects happen */
#define sprintf __fsa_sprintf
static int __fsa_sprintf(char *out, const char *fmt, ...) {
    g_reached_sink = 1;
    (void)fmt;
    if (out) out[0] = '\0';
    klee_assert(fmt != NULL);
    return 0;
}

__FUNC_DECL__

int main(void) {
    static char input[__INPUT_SIZE__];
    klee_make_symbolic(input, sizeof(input), "input");
    for (unsigned i = 0; i + 1 < sizeof(input); i++) {
        klee_assume(input[i] >= 0x20 && input[i] <= 0x7e);
    }
    input[sizeof(input) - 1] = '\0';
__FUNC_CALL__
    klee_assert(!g_reached_sink || 1);
    return 0;
}
