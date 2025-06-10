#pragma once
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "ecc.h"
#include "mpz.h"
#include "sysconf.h"
#include "ec_gf2n.h"
#include "ec_gfp.h"

#define Binary 1
#define Prime 0
#define SHA224 1
#define SHA256 2

#ifdef  __cplusplus
extern "C" {
#endif
	void Private_Key_generator(MPZ* Private_key, ECC_PARAMS SELECTED_CURVE, ECC_ID ecc_id, int HASH_FUNCTION, unsigned char* URAND_VAL, int URAND_len);

	void Public_Key_generator_gfp(ECC_POINT* Public_point, unsigned int* Private_key, ECC_PARAMS SELECTED_CURVE);

	void Public_Key_generator_gf2n(ECC_POINT* Public_point, unsigned int* Private_key, ECC_PARAMS SELECTED_CURVE);

	void eckcdsa_gfp(ECC_POINT Private, ECC_PARAMS SELECTED_CURVE, unsigned int* secret, unsigned int ECC_ID,
		unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len, unsigned char signature[]);

	void eckcdsa_gf2n(ECC_POINT Private, ECC_PARAMS SELECTED_CURVE, unsigned int* secret, unsigned int ECC_ID,
		unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len, unsigned char signature[]);

	int	eckcdsa_gfp_verify(ECC_POINT Private, unsigned char signature[], ECC_PARAMS SELECTED_CURVE,
		unsigned int ECC_ID, unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len);

	int	eckcdsa_gf2n_verify(ECC_POINT Private, unsigned char signature[], ECC_PARAMS SELECTED_CURVE,
		unsigned int ECC_ID, unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len);

	void Public_Key_generator(ECC_POINT* Public_point, unsigned int* Private_key, ECC_PARAMS SELECTED_CURVE);

	void EC_KCDSA_sign(ECC_POINT Public_point, ECC_PARAMS SELECTED_CURVE, unsigned int* secret, unsigned int ECC_ID,
		unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len, unsigned char signature[]);

	int EC_KCDSA_verify(ECC_POINT Public_point, unsigned char signature[], ECC_PARAMS SELECTED_CURVE,
		unsigned int ECC_ID, unsigned int HASH_FUNCTION, unsigned char Message[], int MSG_len);

	void Public_Key_set_params(ECC_POINT* Public_point, ECC_PARAMS SELECTED_CURVE, unsigned int* x_Q, int x_Q_len, unsigned int* y_Q, int y_Q_len);

	void Word_to_Byte(unsigned int* W, unsigned char* C, int W_length, int char_length);
	void Point_to_Byte(unsigned int* W, unsigned char* C, int W_length, int Temp_char_length);
	void Byte_to_Prime_Field(unsigned char* C, unsigned int* Field, int Byte_length, int Field_length);

#ifdef  __cplusplus
}
#endif
