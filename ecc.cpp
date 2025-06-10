#include "ecc.h"
#include "SHA224.h"
#include "SHA256.h"

unsigned char char_bit_trancator(unsigned char IN, int bitlen)
{
	if (bitlen == 1)
		return IN & 1;
	else if (bitlen == 2)
		return IN & 3;
	else if (bitlen == 3)
		return IN & 7;
	else if (bitlen == 4)
		return IN & 0xF;
	else if (bitlen == 5)
		return IN & 0x1F;
	else if (bitlen == 6)
		return IN & 0x3F;
	else if (bitlen == 7)
		return IN & 0x7F;
	else if (bitlen == 0)
		return IN;
	return IN;
}

extern SINT
EC_POINT_LENGTH(int Curve_number)
{
	int length, reduced_length = 0;
	int i = 0;
	unsigned int top_word;

	length = (ecc_params_tab[Curve_number].order_len * 4);
	top_word = ecc_params_tab[Curve_number].ecc_params_buf.base_y_dat[ecc_params_tab[Curve_number].order_len - 1];

	if (ecc_params_tab[Curve_number].field_type == ECC_CHAR2_FIELD)
	{
		while (1)
		{

			if ((top_word >> ((3 - i) * 8) & 0xFF) == 0)
			{
				reduced_length++;
				i++;
			}

			else
				break;
		}
	}

	return length - reduced_length;
}

SINT
ECC_init_params(ECC_FIELD_TYPE	ftype, ECC_PARAMS* ecc_params, const unsigned int ECC_ID) // �ʱ�ȭ 
{
	const ECC_PARAMS_BUF* ecc_params_buf = &ecc_params_tab[ECC_ID].ecc_params_buf;
	if (ftype == ECC_PRIME_FIELD) {
		ecc_params->field_type = ECC_PRIME_FIELD;
		ecc_params->pfield.curve.a.dat = (unsigned int*)ecc_params_buf->coef1_dat;
		ecc_params->pfield.curve.b.dat = (unsigned int*)ecc_params_buf->coef2_dat;
		ecc_params->pfield.curve.prime.dat = (unsigned int*)ecc_params_buf->modulo_dat;
		ecc_params->pfield.base.is_O = 0;
		ecc_params->pfield.base.x.dat = (unsigned int*)ecc_params_buf->base_x_dat;
		ecc_params->pfield.base.y.dat = (unsigned int*)ecc_params_buf->base_y_dat;
	}
	else if (ftype == ECC_CHAR2_FIELD) {
		ecc_params->field_type = ECC_CHAR2_FIELD;
		ecc_params->c2field.curve.a2 = (unsigned int*)ecc_params_buf->coef1_dat;
		ecc_params->c2field.curve.a6 = (unsigned int*)ecc_params_buf->coef2_dat;
		ecc_params->c2field.curve.irr.term = (unsigned int*)ecc_params_buf->modulo_dat;
		ecc_params->c2field.base.is_O = 0;
		ecc_params->c2field.base.x = (unsigned int*)ecc_params_buf->base_x_dat;
		ecc_params->c2field.base.y = (unsigned int*)ecc_params_buf->base_y_dat;
	}
	else
		return -1;
	ecc_params->order.dat = (unsigned int*)ecc_params_buf->order_dat;
	ecc_params->cofactor.dat = (unsigned int*)ecc_params_buf->cofactor_dat;
	return 0;
}

SINT
ECC_set_params(ECC_ID ecc_id, ECC_PARAMS* ecc_params) // ecc id �� Ŀ���� �з� ��ȣ , �з� ��ȣ�� ������ �Ķ���͸� �Է��Ͽ� �Ķ���͸� �����ϴ� �Լ� // ECC_initialize ���Ŀ� �����ؾ� ��ī�� ������ �ȳ�
{
	const ECC_PARAMS_BUF* ecpbufp;
	SINT field_len, order_len, cofactor_len;
	SINT field_bytes, order_bytes, cofactor_bytes;

	if (ecc_params->field_type != ecc_params_tab[ecc_id].field_type)
		return -1; /* ecp is not initialized correctly. */
	ecpbufp = &ecc_params_tab[ecc_id].ecc_params_buf;
	field_len = ecc_params_tab[ecc_id].field_len;
	field_bytes = MAC_MULT2EXP(field_len, 2);
	order_len = ecc_params_tab[ecc_id].order_len;
	order_bytes = MAC_MULT2EXP(order_len, 2);
	cofactor_len = ecc_params_tab[ecc_id].cofactor_len;
	cofactor_bytes = MAC_MULT2EXP(cofactor_len, 2);

	if (ecc_params->field_type == ECC_PRIME_FIELD) {
		/* a */
		ecc_params->pfield.curve.a.len = field_len;
		ecc_params->pfield.curve.a.sig = MPCONST_POS_SIG;

		/* b */
		ecc_params->pfield.curve.b.len = field_len;
		ecc_params->pfield.curve.b.sig = MPCONST_POS_SIG;

		/* prime */
		ecc_params->pfield.curve.prime.len = field_len;
		ecc_params->pfield.curve.prime.sig = MPCONST_POS_SIG;
		/* base is_O */
		ecc_params->pfield.base.is_O = 0;
		/* base x */
		ecc_params->pfield.base.x.len = field_len;
		ecc_params->pfield.base.x.sig = MPCONST_POS_SIG;

		/* base y */
		ecc_params->pfield.base.y.len = field_len;
		ecc_params->pfield.base.y.sig = MPCONST_POS_SIG;

	}
	else if (ecc_params->field_type == ECC_CHAR2_FIELD) {

		ecc_params->c2field.curve.irr.top = ecc_params_tab[ecc_id].gf2n_top;
		ecc_params->c2field.curve.irr.fbits = ecc_params_tab[ecc_id].gf2n_fbits;
		/* base is_O*/
		ecc_params->c2field.base.is_O = 0;
		/* base x */
		/* base y */
	}
	ecc_params->order.sig = MPCONST_POS_SIG;
	ecc_params->order.len = order_len;

	ecc_params->cofactor.sig = MPCONST_POS_SIG;
	ecc_params->cofactor.len = cofactor_len;

	return 0;
}

/*** PRNG ECKCDSA ***/
SINT
Bit_Truncation(unsigned long* IN, const int Truncater_bit_loc)
{
	int Word_t = Truncater_bit_loc / 32;
	int extra_t = Truncater_bit_loc % 32;

	IN[Word_t] = IN[Word_t] % (1 << extra_t);

	return 0;
}

void PRNG_ECKCDSA_SHA224(const unsigned char* SEED, const SINT SEED_char_LENGTH, unsigned char* output, const SINT output_bit_LENGTH)  // output should be initialized
{
	int k, r;   // refer to specification of ECKCDSA
	int output_byte_length, Byte_remainder_bit;
	int Byte_remainder_length = 0, Word_remainder_length = 0;
	int index, j, extra_index = 0;
	SHA224_CTX	AlgInfo;
	const int SHA224_DIGEST_BYTE_LENGTH = 28;
	unsigned char DigestValue[28];
	unsigned char temp_out[200] = { 0, };
	unsigned char SEED_i[200] = { 0, };
	unsigned char Toutput[200] = { 0, };

	/* normal byte legnth computation */
	output_byte_length = output_bit_LENGTH / 8;
	Byte_remainder_bit = output_bit_LENGTH % 8;
	if (Byte_remainder_bit != 0)
		output_byte_length++;

	/* SEED ���� ������ ����Ʈ�� �����ϰ� �Է� */
	for (index = 0; index < SEED_char_LENGTH; index++)
		SEED_i[index] = SEED[index];

	/* general iter */
	k = output_byte_length / SHA224_DIGEST_BYTE_LENGTH;
	/* �ؽ� ������� �������� �ʴ� ������ ����Ʈ�� ���̸� ���� */
	r = output_byte_length % SHA224_DIGEST_BYTE_LENGTH;

	for (index = 0; index < k + 1; index++)
	{
		if ((index == k && r != 0) || ((index == (k - 1)) && r == 0))  // r!=0 �̸� ������ ������ k �̴�. r=0 �̸� ������ ������ k-1 �̴�. 
		{
			SEED_i[SEED_char_LENGTH] = index;

			/* SEED ���Ͽ� ���� �ؽ� ���� */
			SHA224_Init(&AlgInfo);
			SHA224_Update(&AlgInfo, SEED_i, SEED_char_LENGTH + 1);
			SHA224_Final(&AlgInfo, DigestValue);

			if (r != 0)
			{
				for (j = 0; j < r; j++)
					Toutput[j] = DigestValue[SHA224_DIGEST_BYTE_LENGTH - r + j];

				Toutput[0] = char_bit_trancator(Toutput[0], Byte_remainder_bit);
			}
			else
			{
				for (j = 0; j < SHA224_DIGEST_BYTE_LENGTH; j++)
					Toutput[j] = DigestValue[j];

				Toutput[0] = char_bit_trancator(Toutput[0], Byte_remainder_bit);
			}

			if (r == 0)  //
				index++;
		}
		else if (index < k)
		{
			SEED_i[SEED_char_LENGTH] = index;

			/* SEED ���Ͽ� ���� �ؽ� ���� */
			SHA224_Init(&AlgInfo);
			SHA224_Update(&AlgInfo, SEED_i, SEED_char_LENGTH + 1);
			SHA224_Final(&AlgInfo, DigestValue);

			for (j = 0; j < SHA224_DIGEST_BYTE_LENGTH; j++)
				Toutput[r + (SHA224_DIGEST_BYTE_LENGTH * (k - index - 1)) + j] = DigestValue[j];
		}
	}
	for (index = 0; index < output_byte_length; index++)
		output[index] = Toutput[index];
}

void PRNG_ECKCDSA_SHA256(const unsigned char* SEED, const SINT SEED_char_LENGTH, unsigned char* output, const SINT output_bit_LENGTH)  // output should be initialized
{
	int k, r;   // refer to specification of ECKCDSA
	int output_byte_length, Byte_remainder_bit;
	int Byte_remainder_length = 0, Word_remainder_length = 0;
	int index, j, extra_index = 0;
	SHA256_CTX	AlgInfo;
	const int SHA256_DIGEST_BYTE_LENGTH = 32;
	unsigned char DigestValue[32];
	unsigned char temp_out[200] = { 0, };
	unsigned char SEED_i[200] = { 0, };
	unsigned char Toutput[200] = { 0, };


	/* normal byte legnth computation */
	output_byte_length = output_bit_LENGTH / 8;
	Byte_remainder_bit = output_bit_LENGTH % 8;
	if (Byte_remainder_bit != 0)
		output_byte_length++;

	/* SEED ���� ������ ����Ʈ�� �����ϰ� �Է� */
	for (index = 0; index < SEED_char_LENGTH; index++)
		SEED_i[index] = SEED[index];

	/* general iter */
	k = output_byte_length / SHA256_DIGEST_BYTE_LENGTH;
	/* �ؽ� ������� �������� �ʴ� ������ ����Ʈ�� ���̸� ���� */
	r = output_byte_length % SHA256_DIGEST_BYTE_LENGTH;

	for (index = 0; index < k + 1; index++)
	{
		if ((index == k && r != 0) || ((index == (k - 1)) && r == 0))  // r!=0 �̸� ������ ������ k �̴�. r=0 �̸� ������ ������ k-1 �̴�. 
		{
			SEED_i[SEED_char_LENGTH] = index;

			/* SEED ���Ͽ� ���� �ؽ� ���� */
			SHA256_Init(&AlgInfo);
			SHA256_Update(&AlgInfo, SEED_i, SEED_char_LENGTH + 1);
			SHA256_Final(&AlgInfo, DigestValue);

			if (r != 0)
			{
				for (j = 0; j < r; j++)
					Toutput[j] = DigestValue[SHA256_DIGEST_BYTE_LENGTH - r + j];

				Toutput[0] = char_bit_trancator(Toutput[0], Byte_remainder_bit);
			}
			else
			{
				for (j = 0; j < SHA256_DIGEST_BYTE_LENGTH; j++)
					Toutput[j] = DigestValue[j];

				Toutput[0] = char_bit_trancator(Toutput[0], Byte_remainder_bit);
			}

			if (r == 0)  //
				index++;
		}
		else if (index < k)
		{
			SEED_i[SEED_char_LENGTH] = index;

			/* SEED ���Ͽ� ���� �ؽ� ���� */
			SHA256_Init(&AlgInfo);
			SHA256_Update(&AlgInfo, SEED_i, SEED_char_LENGTH + 1);
			SHA256_Final(&AlgInfo, DigestValue);

			for (j = 0; j < SHA256_DIGEST_BYTE_LENGTH; j++)
				Toutput[r + (SHA256_DIGEST_BYTE_LENGTH * (k - index - 1)) + j] = DigestValue[j];
		}
	}

	for (index = 0; index < output_byte_length; index++)
		output[index] = Toutput[index];
}