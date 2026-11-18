/*
 * vulnstr -- KEY=VALUE record parser (CORRECT PATCH).
 *
 * Fix: store_value() now bounds every write against the destination capacity,
 * so a value longer than the buffer is safely truncated instead of overflowing
 * the stack. Valid inputs (value length < 32) are unaffected, so the functional
 * behaviour "KEY:<len>" is preserved for all in-range values.
 *
 * Expected harness verdict against the vulnerable base: exit 0 (PASS).
 */
#include <stdio.h>
#include <string.h>

static void store_value(char *val, size_t cap, const char *value)
{
    size_t j = 0;
    for (const char *p = value; *p != '\0'; ++p) {
        if (j + 1 < cap) {       /* FIX: keep room for the NUL terminator */
            val[j++] = *p;
        }
    }
    val[j] = '\0';
}

static void process_line(char *line)
{
    char *eq = strchr(line, '=');
    if (eq == NULL) {
        return;
    }
    *eq = '\0';
    const char *key = line;
    const char *value = eq + 1;

    char val[32];
    store_value(val, sizeof val, value);
    printf("%s:%d\n", key, (int)strlen(val));
}

static void process_stream(FILE *fp)
{
    char line[4096];
    while (fgets(line, sizeof line, fp) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        process_line(line);
    }
}

/* Input delivery: no arguments -> records on stdin; "-f FILE" -> records in
 * FILE; otherwise every command-line argument is one record. */
int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "-f") == 0) {
        FILE *fp = fopen(argv[2], "r");
        if (fp == NULL) {
            perror(argv[2]);
            return 2;
        }
        process_stream(fp);
        fclose(fp);
        return 0;
    }
    if (argc >= 2) {
        char line[4096];
        for (int i = 1; i < argc; ++i) {
            strncpy(line, argv[i], sizeof line - 1);
            line[sizeof line - 1] = '\0';
            if (line[0] != '\0') {
                process_line(line);
            }
        }
        return 0;
    }
    process_stream(stdin);
    return 0;
}
