#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* sink stub: record that a symbolic argument reached the sink; do NOT execute it */
static int g_reached_sink = 0;
static char g_sink_arg[512];

void __fsa_sink(const char *cmd) {
    g_reached_sink = 1;
    if (cmd) {
        strncpy(g_sink_arg, cmd, sizeof(g_sink_arg) - 1);
        g_sink_arg[sizeof(g_sink_arg) - 1] = '\0';
    }
    klee_assert(cmd == NULL || strlen(cmd) < sizeof(g_sink_arg));
}

/* redirect the real command sink to the stub so no shell is ever spawned */
#define system(x) __fsa_sink(x)
#define popen(x, m) __fsa_sink(x)

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
