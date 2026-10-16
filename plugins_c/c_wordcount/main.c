/* Benign C plugin: counts lines, words and bytes in /data/sample.txt. */
#include <stdio.h>
#include <ctype.h>

int main(void) {
    FILE *f = fopen("/data/sample.txt", "r");
    if (!f) { perror("c_wordcount: open /data/sample.txt"); return 1; }
    long lines = 0, words = 0, bytes = 0;
    int c, in_word = 0;
    while ((c = fgetc(f)) != EOF) {
        bytes++;
        if (c == '\n') lines++;
        if (isspace(c)) in_word = 0;
        else if (!in_word) { in_word = 1; words++; }
    }
    fclose(f);
    printf("c_wordcount: %ld lines, %ld words, %ld bytes\n", lines, words, bytes);
    return 0;
}