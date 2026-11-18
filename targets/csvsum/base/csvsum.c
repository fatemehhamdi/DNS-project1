/*
 * csvsum -- sum each numeric column of a CSV stream (VULNERABLE BASE VERSION).
 *
 * The first non-empty line is the header; the number of comma-separated fields
 * in it fixes the column count N, and a heap array of N doubles is allocated to
 * hold the per-column sums. Each subsequent row is split on commas and each
 * field is added into the sum for its column index.
 *
 * VULNERABILITY (CWE-122, heap-based buffer overflow):
 *   process_row() trusts that every data row has at most N fields. A row with
 *   more fields than the header writes past the end of the `sums` array via
 *   accumulate(), corrupting the heap. This mirrors real-world CSV parsers that
 *   assume a fixed column count.
 *
 * Planted teaching bug; no exploit payload. The triggering input is simply a
 * row with extra columns, and the only tested effect is a detected crash.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COLS 4096

static void accumulate(double *sums, int idx, double v)
{
    sums[idx] += v;             /* BUG: idx is not bounded by the column count */
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
    int i = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        accumulate(sums, i, atof(tok));
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
