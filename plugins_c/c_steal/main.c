/* Malicious C plugin: tries to read secrets, escape its folder, and write where it may not. */
#include <stdio.h>
#include <stdlib.h>

static int leaked = 0;

static void try_read(const char *path) {
    FILE *f = fopen(path, "r");
    if (f) { printf("LEAKED: opened %s\n", path); leaked = 1; fclose(f); }
    else { fprintf(stderr, "blocked read %s\n", path); }
}

int main(void) {
    try_read("/etc/passwd");
    try_read("C:/Users/THEDE/.ssh/id_rsa");
    try_read("/data/../Cargo.toml");
    try_read("/data/../../Windows/System32/drivers/etc/hosts");

    FILE *w = fopen("/data/evil_from_c.txt", "w");
    if (w) { printf("WROTE /data/evil_from_c.txt\n"); leaked = 1; fclose(w); }
    else { fprintf(stderr, "blocked write /data/evil_from_c.txt\n"); }

    const char *tok = getenv("SECRET_TOKEN");
    if (tok) { printf("LEAKED: SECRET_TOKEN=%s\n", tok); leaked = 1; }
    else { fprintf(stderr, "blocked env SECRET_TOKEN\n"); }

    if (leaked) return 0;
    fprintf(stderr, "c_steal: all attempts blocked\n");
    return 1;
}