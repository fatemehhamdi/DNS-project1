/*
 * csvsum -- sum each numeric column of a CSV stream (INCOMPLETE PATCH).
 *
 * Attempted fix: rows with "too many" fields (more than 32) are skipped, which
 * blocks the original very-wide crasher. But rows with more fields than the
 * header and at most 32 fields are still accumulated with no per-index bound,
 * so the same heap overflow is reachable through a moderately wide row.
 *
 * Expected harness verdict against the vulnerable base: exit 10
 * (VULN_REMAINS / INCOMPLETE_FIX).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COLS 4096

static void accumulate(double *sums, int idx, double v)
{
    sums[idx] += v;
}

static int count_fields(const char *line)
{
    int n = 1;
    for (const char *p = line; *p; ++p) {
        if (*p == ',') {
            n++;
        }
    }
    return n;
}

static void process_row(double *sums, int ncols, char *line)
{
    (void)ncols;
    if (count_fields(line) > 32) {   /* incomplete guard: only very wide rows */
        return;
    }
    int i = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        accumulate(sums, i, atof(tok));   /* STILL UNBOUNDED */
        i++;
    }
}

int main(void)
{
    char line[8192];
    char *names[MAX_COLS];
    int ncols = 0;
    double *sums = NULL;
    int have_header = 0;

    while (fgets(line, sizeof line, stdin) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] == '\0') {
            continue;
        }
        if (!have_header) {
            ncols = count_fields(line);
            if (ncols > MAX_COLS) {
                ncols = MAX_COLS;
            }
            char *save = NULL;
            int k = 0;
            for (char *tok = strtok_r(line, ",", &save);
                 tok != NULL && k < ncols;
                 tok = strtok_r(NULL, ",", &save)) {
                names[k++] = strdup(tok);
            }
            ncols = k;
            sums = (double *)calloc((size_t)ncols, sizeof(double));
            if (sums == NULL) {
                return 3;
            }
            have_header = 1;
        } else {
            process_row(sums, ncols, line);
        }
    }

    for (int i = 0; i < ncols; ++i) {
        printf("%s=%g\n", names[i], sums[i]);
        free(names[i]);
    }
    free(sums);
    return 0;
}
