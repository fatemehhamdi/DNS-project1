/* Minimal CLI harness around cJSON_Minify for the patchval dynamic test.
 * Reads JSON text from stdin into an exactly-sized heap buffer (so any
 * out-of-bounds access during minification is caught by AddressSanitizer),
 * minifies it in place, and writes the result to stdout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"

int main(void)
{
    static char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof(buf) - 1, stdin);
    buf[n] = '\0';
    char *copy = (char *)malloc(n + 1);
    if (copy == NULL) {
        return 3;
    }
    memcpy(copy, buf, n + 1);
    cJSON_Minify(copy);
    fputs(copy, stdout);
    free(copy);
    return 0;
}
