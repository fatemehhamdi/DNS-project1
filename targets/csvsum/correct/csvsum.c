/*
 * csvsum -- sum each numeric column of a CSV stream (CORRECT PATCH).
 *
 * Fix: process_row() now bounds the column index against the real column count
 * before accumulating, so extra fields in a data row are ignored instead of
 * writing past the `sums` array. Well-formed input (rows with <= N fields) is
 * summed exactly as before.
 *
 * Expected harness verdict against the vulnerable base: exit 0 (PASS).
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
    int i = 0;
    char *save = NULL;
    for (char *tok = strtok_r(line, ",", &save); tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        if (i < ncols) {         /* FIX: never write past the sums array */
            accumulate(sums, i, atof(tok));
        }
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
