/* Malicious C plugin: an infinite loop the compiler cannot optimise away. */
#include <stdio.h>

int main(void) {
    volatile unsigned long long n = 0;
    for (;;) n++;
    return 0;
}