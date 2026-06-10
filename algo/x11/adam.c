#include "cpuminer-config.h"
#include "adam-gate.h"

#if !defined(X11_8WAY) && !defined(X11_4WAY)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/sha/sha256d.h"

#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/simd/sph_simd.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/echo/sph_echo.h"

#if defined(__AES__)
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#endif
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/haval/sph-haval.h"

typedef struct
{
	sph_blake512_context blake;
	sph_bmw512_context bmw;
#if defined(__AES__)
	hashState_echo echo;
	hashState_groestl groestl;
#else
	sph_groestl512_context groestl;
	sph_echo512_context echo;
#endif
	sph_jh512_context jh;
	sph_keccak512_context keccak;
	sph_skein512_context skein;
	hashState_luffa luffa;
	cubehashParam cube;
	sph_shavite512_context shavite;
	hashState_sd simd;
} adam_ctx_holder;

adam_ctx_holder adam_ctx;

void init_adam_ctx()
{
	sph_blake512_init(&adam_ctx.blake);
	sph_bmw512_init(&adam_ctx.bmw);
#if defined(__AES__)
	init_groestl(&adam_ctx.groestl, 64);
	init_echo(&adam_ctx.echo, 512);
#else
	sph_groestl512_init(&adam_ctx.groestl);
	sph_echo512_init(&adam_ctx.echo);
#endif
	sph_skein512_init(&adam_ctx.skein);
	sph_jh512_init(&adam_ctx.jh);
	sph_keccak512_init(&adam_ctx.keccak);
	init_luffa(&adam_ctx.luffa, 512);
	cubehashInit(&adam_ctx.cube, 512, 16, 32);
	sph_shavite512_init(&adam_ctx.shavite);
	init_sd(&adam_ctx.simd, 512);
}

const unsigned int HASHADAM_MIN_NUMBER_ITERATIONS = 2;
const unsigned int HASHADAM_MAX_NUMBER_ITERATIONS = 6;
const unsigned int HASHADAM_NUMBER_ALGOS = 11;

void adam_kv(void *state, const void *input)
{
	unsigned char hash[64] __attribute__((aligned(64)));
	unsigned char *p;
	adam_ctx_holder ctx;
	memcpy(&ctx, &adam_ctx, sizeof(adam_ctx));

	sph_blake512(&ctx.blake, input, 80);
	sph_blake512_close(&ctx.blake, hash);

	p = (unsigned char *)hash;
	unsigned int n = HASHADAM_MIN_NUMBER_ITERATIONS + (p[63] % (HASHADAM_MAX_NUMBER_ITERATIONS - HASHADAM_MIN_NUMBER_ITERATIONS + 1));

	for (int i = 1; i < n; i++)
	{
		p = (unsigned char *)hash;
		switch (p[i] % 11)
		{
		case 0:
			sph_blake512_init(&ctx.blake);
			sph_blake512(&ctx.blake, (const void *)hash, 64);
			sph_blake512_close(&ctx.blake, hash);
			break;
		case 1:
			sph_bmw512_init(&ctx.bmw);
			sph_bmw512(&ctx.bmw, (const void *)hash, 64);
			sph_bmw512_close(&ctx.bmw, hash);
			break;
		case 2:
#if defined(__AES__)
			init_groestl(&ctx.groestl, 64);
			update_and_final_groestl(&ctx.groestl, (char *)hash,
									 (const char *)hash, 512);
#else
			sph_groestl512_init(&ctx.groestl);
			sph_groestl512(&ctx.groestl, hash, 64);
			sph_groestl512_close(&ctx.groestl, hash);
#endif
			break;
		case 3:
			sph_skein512_init(&ctx.skein);
			sph_skein512(&ctx.skein, (const void *)hash, 64);
			sph_skein512_close(&ctx.skein, hash);
			break;
		case 4:
			sph_jh512_init(&ctx.jh);
			sph_jh512(&ctx.jh, (const void *)hash, 64);
			sph_jh512_close(&ctx.jh, hash);
			break;
		case 5:
			sph_keccak512_init(&ctx.keccak);
			sph_keccak512(&ctx.keccak, (const void *)hash, 64);
			sph_keccak512_close(&ctx.keccak, hash);
			break;
		case 6:
			init_luffa(&ctx.luffa, 512);
			update_luffa(&ctx.luffa, (const BitSequence *)hash, 64);
			final_luffa(&ctx.luffa, (BitSequence *)hash);
			break;
		case 7:
			cubehashInit(&ctx.cube, 512, 16, 32);
			cubehashUpdate(&ctx.cube, (const byte *)hash, 64);
			cubehashDigest(&ctx.cube, (byte *)hash);
			break;
		case 8:
			sph_shavite512_init(&ctx.shavite);
			sph_shavite512(&ctx.shavite, hash, 64);
			sph_shavite512_close(&ctx.shavite, hash);
			break;
		case 9:
			init_sd(&ctx.simd, 512);
			update_sd(&ctx.simd, (const BitSequence *)hash, 512);
			final_sd(&ctx.simd, (BitSequence *)hash);
			break;
		case 10:
#if defined(__AES__)
			init_echo(&ctx.echo, 512);
			update_final_echo(&ctx.echo, (BitSequence *)hash,
							  (const BitSequence *)hash, 512);
#else
			sph_echo512_init(&ctx.echo);
			sph_echo512(&ctx.echo, hash, 64);
			sph_echo512_close(&ctx.echo, hash);
#endif
			break;
		}
	}

	memcpy(state, hash, 32);
}

void adam_kv_70(void *state, const void *input)
{
	unsigned char hash[64] __attribute__((aligned(64)));
	unsigned char *p;
	adam_ctx_holder ctx;
	memcpy(&ctx, &adam_ctx, sizeof(adam_ctx));

	sph_blake512(&ctx.blake, input, 70);
	sph_blake512_close(&ctx.blake, hash);

	p = (unsigned char *)hash;
	unsigned int n = HASHADAM_MIN_NUMBER_ITERATIONS + (p[63] % (HASHADAM_MAX_NUMBER_ITERATIONS - HASHADAM_MIN_NUMBER_ITERATIONS + 1));

	for (int i = 1; i < n; i++)
	{
		p = (unsigned char *)hash;
		switch (p[i] % 11)
		{
		case 0:
			sph_blake512_init(&ctx.blake);
			sph_blake512(&ctx.blake, (const void *)hash, 64);
			sph_blake512_close(&ctx.blake, hash);
			break;
		case 1:
			sph_bmw512_init(&ctx.bmw);
			sph_bmw512(&ctx.bmw, (const void *)hash, 64);
			sph_bmw512_close(&ctx.bmw, hash);
			break;
		case 2:
#if defined(__AES__)
			init_groestl(&ctx.groestl, 64);
			update_and_final_groestl(&ctx.groestl, (char *)hash,
									 (const char *)hash, 512);
#else
			sph_groestl512_init(&ctx.groestl);
			sph_groestl512(&ctx.groestl, hash, 64);
			sph_groestl512_close(&ctx.groestl, hash);
#endif
			break;
		case 3:
			sph_skein512_init(&ctx.skein);
			sph_skein512(&ctx.skein, (const void *)hash, 64);
			sph_skein512_close(&ctx.skein, hash);
			break;
		case 4:
			sph_jh512_init(&ctx.jh);
			sph_jh512(&ctx.jh, (const void *)hash, 64);
			sph_jh512_close(&ctx.jh, hash);
			break;
		case 5:
			sph_keccak512_init(&ctx.keccak);
			sph_keccak512(&ctx.keccak, (const void *)hash, 64);
			sph_keccak512_close(&ctx.keccak, hash);
			break;
		case 6:
			init_luffa(&ctx.luffa, 512);
			update_luffa(&ctx.luffa, (const BitSequence *)hash, 64);
			final_luffa(&ctx.luffa, (BitSequence *)hash);
			break;
		case 7:
			cubehashInit(&ctx.cube, 512, 16, 32);
			cubehashUpdate(&ctx.cube, (const byte *)hash, 64);
			cubehashDigest(&ctx.cube, (byte *)hash);
			break;
		case 8:
			sph_shavite512_init(&ctx.shavite);
			sph_shavite512(&ctx.shavite, hash, 64);
			sph_shavite512_close(&ctx.shavite, hash);
			break;
		case 9:
			init_sd(&ctx.simd, 512);
			update_sd(&ctx.simd, (const BitSequence *)hash, 512);
			final_sd(&ctx.simd, (BitSequence *)hash);
			break;
		case 10:
#if defined(__AES__)
			init_echo(&ctx.echo, 512);
			update_final_echo(&ctx.echo, (BitSequence *)hash,
							  (const BitSequence *)hash, 512);
#else
			sph_echo512_init(&ctx.echo);
			sph_echo512(&ctx.echo, hash, 64);
			sph_echo512_close(&ctx.echo, hash);
#endif
			break;
		}
	}

	memcpy(state, hash, 32);
}

const uint32_t HASHADAM_MAX_LEVEL = 7;
const uint32_t HASHADAM_MIN_LEVEL = 1;
const uint32_t HASHADAM_MAX_DRIFT = 0xFFFF;
const uint32_t HASHADAM_CACHE_CHUNK = 33;
const uint32_t HASHADAM_CACHE_POSITIONS = 0xFFFF;
const uint32_t HASHADAM_CACHE_POSITIONS_2 = 0xFFFF * 2;
const uint32_t HASHADAM_CACHE_POSITIONS_3 = 0xFFFF * 3;
const uint32_t HASHADAM_CACHE_POSITIONS_4 = 0xFFFF * 4;
const uint32_t HASHADAM_CACHE_POSITIONS_5 = 0xFFFF * 5;
const uint32_t HASHADAM_CACHE_POSITIONS_6 = 0xFFFF * 6;
const uint32_t HASHADAM_CACHE_SIZE = 0xFFFF * 33;
const uint32_t HASHADAM_CACHE_SIZE_2 = 0xFFFF * 33 + 0xFFFF * 33 * 2;
const uint32_t HASHADAM_CACHE_SIZE_3 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3;
const uint32_t HASHADAM_CACHE_SIZE_4 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4;
const uint32_t HASHADAM_CACHE_SIZE_5 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4 + 0xFFFF * 33 * 5;
const uint32_t HASHADAM_CACHE_SIZE_6 = 0xFFFF * 33 + 0xFFFF * 33 * 2 + 0xFFFF * 33 * 3 + 0xFFFF * 33 * 4 + 0xFFFF * 33 * 5 + 0xFFFF * 33 * 6;

void adam_base_hash_recursive(void *output, const void *input, uint32_t level, uint32_t nonce, uint8_t *cache)
{
	if (cache)
	{
		if (level == HASHADAM_MAX_LEVEL - 1 && cache[(nonce % HASHADAM_CACHE_POSITIONS) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + ((nonce % HASHADAM_CACHE_POSITIONS) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHADAM_MAX_LEVEL - 2 && cache[HASHADAM_CACHE_SIZE + (nonce % HASHADAM_CACHE_POSITIONS_2) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHADAM_CACHE_SIZE + ((nonce % HASHADAM_CACHE_POSITIONS_2) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHADAM_MAX_LEVEL - 3 && cache[HASHADAM_CACHE_SIZE_2 + (nonce % HASHADAM_CACHE_POSITIONS_3) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHADAM_CACHE_SIZE_2 + ((nonce % HASHADAM_CACHE_POSITIONS_3) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHADAM_MAX_LEVEL - 4 && cache[HASHADAM_CACHE_SIZE_3 + (nonce % HASHADAM_CACHE_POSITIONS_4) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHADAM_CACHE_SIZE_3 + ((nonce % HASHADAM_CACHE_POSITIONS_4) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHADAM_MAX_LEVEL - 5 && cache[HASHADAM_CACHE_SIZE_4 + (nonce % HASHADAM_CACHE_POSITIONS_5) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHADAM_CACHE_SIZE_4 + ((nonce % HASHADAM_CACHE_POSITIONS_5) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}

		if (level == HASHADAM_MAX_LEVEL - 6 && cache[HASHADAM_CACHE_SIZE_5 + (nonce % HASHADAM_CACHE_POSITIONS_6) * HASHADAM_CACHE_CHUNK] == 0xFF)
		{ // cache hit
			memcpy(output, cache + HASHADAM_CACHE_SIZE_5 + ((nonce % HASHADAM_CACHE_POSITIONS_6) * HASHADAM_CACHE_CHUNK) + 1, 32);
			return;
		}
	}

	uint8_t hash[96];
	adam_kv(hash, input);

	if (level == HASHADAM_MIN_LEVEL)
	{
		memcpy(output, hash, 32);
		if (cache)
		{
			cache[HASHADAM_CACHE_SIZE_5 + (nonce % HASHADAM_CACHE_POSITIONS_6) * HASHADAM_CACHE_CHUNK] = 0xFF;
			memcpy(cache + HASHADAM_CACHE_SIZE_5 + ((nonce % HASHADAM_CACHE_POSITIONS_6) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		}
		return;
	}

	if (cache && level == HASHADAM_MAX_LEVEL)
	{
		// cache clean
		cache[((nonce - 1) % HASHADAM_CACHE_POSITIONS) * HASHADAM_CACHE_CHUNK] = 0x00;
		cache[HASHADAM_CACHE_SIZE + ((nonce - 1) % HASHADAM_CACHE_POSITIONS_2) * HASHADAM_CACHE_CHUNK] = 0x00;
		cache[HASHADAM_CACHE_SIZE_2 + ((nonce - 1) % HASHADAM_CACHE_POSITIONS_3) * HASHADAM_CACHE_CHUNK] = 0x00;
		cache[HASHADAM_CACHE_SIZE_3 + ((nonce - 1) % HASHADAM_CACHE_POSITIONS_4) * HASHADAM_CACHE_CHUNK] = 0x00;
		cache[HASHADAM_CACHE_SIZE_4 + ((nonce - 1) % HASHADAM_CACHE_POSITIONS_5) * HASHADAM_CACHE_CHUNK] = 0x00;
		cache[HASHADAM_CACHE_SIZE_5 + ((nonce - 1) % HASHADAM_CACHE_POSITIONS_6) * HASHADAM_CACHE_CHUNK] = 0x00;
	}

	uint8_t nextheader1[80];
	uint8_t nextheader2[80];

	uint32_t nextnonce1 = nonce + (le32dec(hash + 24) % HASHADAM_MAX_DRIFT);
	uint32_t nextnonce2 = nonce + (le32dec(hash + 28) % HASHADAM_MAX_DRIFT);

	memcpy(nextheader1, input, 76);
	le32enc(nextheader1 + 76, nextnonce1);

	memcpy(nextheader2, input, 76);
	le32enc(nextheader2 + 76, nextnonce2);

	adam_base_hash_recursive(hash + 32, nextheader1, level - 1, nextnonce1, cache);
	adam_base_hash_recursive(hash + 64, nextheader2, level - 1, nextnonce2, cache);

	sha256d(output, hash, 96);

	// cache store
	if (cache && level == HASHADAM_MAX_LEVEL - 1)
	{
		cache[(nonce % HASHADAM_CACHE_POSITIONS) * HASHADAM_CACHE_CHUNK] = 0xFF;
		memcpy(cache + ((nonce % HASHADAM_CACHE_POSITIONS) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHADAM_MAX_LEVEL - 2)
	{
		cache[HASHADAM_CACHE_SIZE + (nonce % HASHADAM_CACHE_POSITIONS_2) * HASHADAM_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHADAM_CACHE_SIZE + ((nonce % HASHADAM_CACHE_POSITIONS_2) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHADAM_MAX_LEVEL - 3)
	{
		cache[HASHADAM_CACHE_SIZE_2 + (nonce % HASHADAM_CACHE_POSITIONS_3) * HASHADAM_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHADAM_CACHE_SIZE_2 + ((nonce % HASHADAM_CACHE_POSITIONS_3) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHADAM_MAX_LEVEL - 4)
	{
		cache[HASHADAM_CACHE_SIZE_3 + (nonce % HASHADAM_CACHE_POSITIONS_4) * HASHADAM_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHADAM_CACHE_SIZE_3 + ((nonce % HASHADAM_CACHE_POSITIONS_4) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		return;
	}

	if (cache && level == HASHADAM_MAX_LEVEL - 5)
	{
		cache[HASHADAM_CACHE_SIZE_4 + (nonce % HASHADAM_CACHE_POSITIONS_5) * HASHADAM_CACHE_CHUNK] = 0xFF;
		memcpy(cache + HASHADAM_CACHE_SIZE_4 + ((nonce % HASHADAM_CACHE_POSITIONS_5) * HASHADAM_CACHE_CHUNK) + 1, output, 32);
		return;
	}
}

void adam_base_hash(void *state, const void *input, uint8_t *cache)
{
	adam_base_hash_recursive(state, input, HASHADAM_MAX_LEVEL, le32dec(((uint8_t *)input) + 76), cache);
}

void adam_hash(void *output, const void *input, const char *powalgo)
{
	unsigned char input70[70];
	memcpy(input70, input, 66);
	uint32_t nonce = le32dec(((const uint8_t *)input) + 76);
	le32enc(input70 + 66, nonce);

	unsigned char hash512[64] __attribute__((aligned(64)));

	if (strcmp(powalgo, "blake") == 0) {
		sph_blake512_context ctx;
		sph_blake512_init(&ctx);
		sph_blake512(&ctx, input70, 70);
		sph_blake512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "bmw") == 0) {
		sph_bmw512_context ctx;
		sph_bmw512_init(&ctx);
		sph_bmw512(&ctx, input70, 70);
		sph_bmw512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "groestl") == 0) {
		sph_groestl512_context ctx;
		sph_groestl512_init(&ctx);
		sph_groestl512(&ctx, input70, 70);
		sph_groestl512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "jh") == 0) {
		sph_jh512_context ctx;
		sph_jh512_init(&ctx);
		sph_jh512(&ctx, input70, 70);
		sph_jh512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "keccak") == 0) {
		sph_keccak512_context ctx;
		sph_keccak512_init(&ctx);
		sph_keccak512(&ctx, input70, 70);
		sph_keccak512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "skein") == 0) {
		sph_skein512_context ctx;
		sph_skein512_init(&ctx);
		sph_skein512(&ctx, input70, 70);
		sph_skein512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "luffa") == 0) {
		sph_luffa512_context ctx;
		sph_luffa512_init(&ctx);
		sph_luffa512(&ctx, input70, 70);
		sph_luffa512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "cubehash") == 0) {
		sph_cubehash512_context ctx;
		sph_cubehash512_init(&ctx);
		sph_cubehash512(&ctx, input70, 70);
		sph_cubehash512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "shavite") == 0) {
		sph_shavite512_context ctx;
		sph_shavite512_init(&ctx);
		sph_shavite512(&ctx, input70, 70);
		sph_shavite512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "simd") == 0) {
		sph_simd512_context ctx;
		sph_simd512_init(&ctx);
		sph_simd512(&ctx, input70, 70);
		sph_simd512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "echo") == 0) {
		sph_echo512_context ctx;
		sph_echo512_init(&ctx);
		sph_echo512(&ctx, input70, 70);
		sph_echo512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "X11KVS") == 0 || strcmp(powalgo, "ADAM") == 0) {
		adam_kv_70(output, input70);
	} else if (strcmp(powalgo, "DoubleSHA256") == 0) {
		sha256d(output, input70, 70);
	} else if (strcmp(powalgo, "hamsi") == 0) {
		sph_hamsi512_context ctx;
		sph_hamsi512_init(&ctx);
		sph_hamsi512(&ctx, input70, 70);
		sph_hamsi512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "fugue") == 0) {
		sph_fugue512_context ctx;
		sph_fugue512_init(&ctx);
		sph_fugue512(&ctx, input70, 70);
		sph_fugue512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "shabal") == 0) {
		sph_shabal512_context ctx;
		sph_shabal512_init(&ctx);
		sph_shabal512(&ctx, input70, 70);
		sph_shabal512_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "whirlpool") == 0) {
		sph_whirlpool_context ctx;
		sph_whirlpool_init(&ctx);
		sph_whirlpool(&ctx, input70, 70);
		sph_whirlpool_close(&ctx, hash512);
		memcpy(output, hash512, 32);
	} else if (strcmp(powalgo, "haval") == 0) {
		sph_haval256_5_context ctx;
		sph_haval256_5_init(&ctx);
		sph_haval256_5(&ctx, input70, 70);
		sph_haval256_5_close(&ctx, output);
	} else {
		sha256d(output, input70, 70);
	}
}

int scanhash_adam(struct work *work, uint32_t max_nonce,
				  uint64_t *hashes_done, struct thr_info *mythr)
{
	uint32_t endiandata[20] __attribute__((aligned(64)));
	uint32_t hash64[8] __attribute__((aligned(64)));
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	int thr_id = mythr->id;
	const uint32_t Htarg = ptarget[7];

	if (work->is_puzzle) {
		do {
			pdata[19] = ++n;
			adam_hash(hash64, pdata, work->pow_algo ? work->pow_algo : "DoubleSHA256");
			if (fulltest(hash64, ptarget)) {
				submit_solution(work, hash64, mythr);
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);

		*hashes_done = n - first_nonce + 1;
		pdata[19] = n;
		return 0;
	}
	uint64_t htmax[] = {
		0,
		0xF,
		0xFF,
		0xFFF,
		0xFFFF,
		0x10000000};
	uint32_t masks[] = {
		0xFFFFFFFF,
		0xFFFFFFF0,
		0xFFFFFF00,
		0xFFFFF000,
		0xFFFF0000,
		0};

	uint8_t *cache = (uint8_t*) malloc(HASHADAM_CACHE_SIZE_6);

	memset(cache, 0x00, HASHADAM_CACHE_SIZE_6);

	// big endian encode 0..18 uint32_t, 64 bits at a time
	swab32_array(endiandata, pdata, 20);

	for (int m = 0; m < 6; m++)
	{
		if (Htarg <= htmax[m])
		{
			uint32_t mask = masks[m];
			do
			{
				pdata[19] = ++n;
				le32enc(&endiandata[19], n);
				adam_base_hash(hash64, &endiandata, cache);

				if ((hash64[7] & mask) == 0)
				{
					if (fulltest(hash64, ptarget))
					{
						pdata[19] = bswap_32(pdata[19]);
						submit_solution(work, hash64, mythr);
					}
				}
			} while (n < max_nonce && !work_restart[thr_id].restart);
		}
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	free(cache);
	return 0;
}
#endif
