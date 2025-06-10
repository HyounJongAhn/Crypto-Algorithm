#pragma once
#include "rsa.h"
#include "bignum.h"
#include "rsa_oaep.h"
#include "rsa_pss.h"
#include "ctr_drbg.h"
int dummy_rng(void* unused);
int rsa_genkey();
int rsa_pss();
int rsa_oaep();
int DoSignature(int num);