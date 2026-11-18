/*
 * vulnstr -- a tiny KEY=VALUE record parser (VULNERABLE BASE VERSION).
 *
 * Reads lines of the form "KEY=VALUE" from stdin and prints "KEY:<len>" where
 * <len> is the length of VALUE. The value is copied into a fixed-size stack
 * buffer.
 *
 * VULNERABILITY (CWE-121, stack-based buffer overflow):
 *   store_value() copies the value byte-by-byte with no bound against the size
 *   of the destination buffer `val[32]`. A value of 32 or more bytes writes
 *   past the buffer and corrupts the stack.
 *
 * This is a deliberately planted, self-contained teaching bug used to exercise
 * a patch-validation harness. It contains no exploit payload -- the input that
 * triggers it is simply a long string, and the only observable effect under
 * test is a detected crash.
 */
#include <stdio.h>
#include <string.h>

static void store_value(char *val, const char *value)
{
    int j = 0;
    for (const char *p = value; *p != '\0'; ++p) {
        val[j++] = *p;          /* BUG: no bound on j against sizeof(val) */
    }
    val[j] = '\0';
}

static void process_line(char *line)
{
    char *eq = strchr(line, '=');
    if (eq == NULL) {
        return;                 /* not a KEY=VALUE record; ignore */
    }
    *eq = '\0';
    const char *key = line;
    const char *value = eq + 1;

    char val[32];
    store_value(val, value);
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
