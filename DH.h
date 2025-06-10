#pragma once
#include "bignum.h"  
#include "RSA.h"
#include "ctr_drbg.h"
#include <time.h>

typedef struct {
	mpi p;			// Z_p
	mpi g;			// generater g
	mpi x;			// private x
	mpi R;			// g^x or g^y
	mpi key;
} DH;


void DH_init(DH* dh_ctx);
void DH_keyExchange(DH* dh_ctx1, DH* dh_ctx2);
void DH_Free(DH* dh_ctx);
int DoDH();