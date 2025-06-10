#include "DH.h"

void DH_init(DH* dh_ctx)
{
	CTR_DRBG_CTX drbg;
	uint8_t entropy[48] = { 0x00, };
	for (int i = 0; i < 48; i++) entropy[i] = 0;
	ctr_drbg_instantiate(&drbg, entropy, 48, NULL, 0);

	mpi_init(&dh_ctx->p, &dh_ctx->g, &dh_ctx->x, &dh_ctx->R, &dh_ctx->key, NULL);

	mpi_gen_prime(&dh_ctx->p, 2048, 0, CTR_DRBG_RNG, &drbg);
	mpi_gen_prime(&dh_ctx->g, 1024, 0, CTR_DRBG_RNG, &drbg);
	ctr_drbg_clear(&drbg);

	srand(time(NULL));
	for (int i = 0; i < 48; i++) entropy[i] = rand() & 0xFF;

	ctr_drbg_instantiate(&drbg, entropy, 48, NULL, 0);
	mpi_gen_prime(&dh_ctx->x, 512, 0, CTR_DRBG_RNG, &drbg);
	ctr_drbg_clear(&drbg);

	return;
}

void DH_keyExchange(DH* dh_ctx1, DH* dh_ctx2)
{
	mpi_exp_mod(&dh_ctx1->R, &dh_ctx1->g, &dh_ctx1->x, &dh_ctx1->p, NULL);  // R1 = g^x mod p
	mpi_exp_mod(&dh_ctx2->R, &dh_ctx2->g, &dh_ctx2->x, &dh_ctx2->p, NULL);  // R2 = g^y mod p

	mpi_exp_mod(&dh_ctx1->key, &dh_ctx2->R, &dh_ctx1->x, &dh_ctx1->p, NULL);  // key = (g^y)^x mod p
	mpi_exp_mod(&dh_ctx2->key, &dh_ctx1->R, &dh_ctx2->x, &dh_ctx2->p, NULL);  // key = (g^x)^y mod p

	return;
}

void DH_Free(DH* dh_ctx)
{
	mpi_free(&dh_ctx->p, &dh_ctx->g, &dh_ctx->x, &dh_ctx->R, &dh_ctx->key, NULL);
	return;
}
int DoDH()
{
	DH Alice_DH;
	DH Bob_DH;
	DH_init(&Alice_DH);
	DH_init(&Bob_DH);

	DH_keyExchange(&Alice_DH, &Bob_DH);

	printf("\nAlice Key: 0x");
	mpi_write_file((char*)"  ", &Alice_DH.key, 16, stdout);

	printf("\nBob Key: 0x");
	mpi_write_file((char*)"  ", &Bob_DH.key, 16, stdout);

	DH_Free(&Alice_DH);
	DH_Free(&Bob_DH);

	return 0;
}