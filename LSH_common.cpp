#include <stdlib.h>
#include <stdio.h>
#include "LSH_common.h"

void print32(u32* data, int len) {
	int i;
	for (i = 0; i < len - 1; i++) printf("%08x ", data[i]);
	printf("%08x\n", data[len - 1]);
}

void print64(u64* data, int len) {
	int i;
	for (i = 0; i < len - 1; i++) printf("%016llx ", data[i]);
	printf("%016llx\n", data[len - 1]);
}
