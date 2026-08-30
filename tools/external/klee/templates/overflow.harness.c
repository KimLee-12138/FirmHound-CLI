#include <klee/klee.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int g_reached_sink = 0;

void __fsa_sink(const char *p) {
    g_reached_sink = 1;
    klee_assert(p != NULL);
}

/* stubbed unsafe copy: copies without bounds so KLEE can observe the OOB write */
static char *__fsa_strcpy(char *d, const char *s) {
    if (d && s) { while ((*d++ = *s++)); }
    return d;
}
static char *__fsa_strcat(char *d, const char *s) {
    if (d && s) { char *t = d; while (*t) t++; while ((*t++ = *s++)); }
    return d;
}

#define strcpy(d, s) __fsa_strcpy(d, s)
#define strcat(d, s) __fsa_strcat(d, s)

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
