/*
 * vulnstr -- KEY=VALUE record parser (INCOMPLETE PATCH).
 *
 * Attempted fix: a length guard is added in process_line(), but it only runs
 * for keys that begin with 'n' (e.g. "name"). store_value() itself is left
 * unbounded. As a result:
 *   - "name=<very long>"  is blocked by the guard (the original crasher), but
 *   - "data=<very long>"  still reaches the unbounded copy and overflows.
 *
 * This models a fix that closes the one input the author tested while leaving
 * the same vulnerability class reachable through a different input.
 *
 * Expected harness verdict against the vulnerable base: exit 10
 * (VULN_REMAINS / INCOMPLETE_FIX).
 */
#include <stdio.h>
#include <string.h>

static void store_value(char *val, const char *value)
{
    int j = 0;
    for (const char *p = value; *p != '\0'; ++p) {
        val[j++] = *p;          /* STILL UNBOUNDED */
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
    /* Incomplete guard: only length-checks keys starting with 'n'. */
    if (key[0] == 'n' && strlen(value) >= sizeof val) {
        return;
    }
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
