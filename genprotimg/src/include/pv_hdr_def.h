/*
 * PV header definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_HDR_DEF_H
#define PV_HDR_DEF_H

#include <openssl/sha.h>

#include "boot/psw.h"
#include "lib/zt_common.h"
#include "utils/crypto.h"

#include "pv_crypto_def.h"

/* Magic number which is used to identify the file containing the PV
 * header
 */
#define PV_MAGIC_NUMBER 0x49424d5365634578ULL
#define PV_VERSION_1	0x00000100U

/* Internal helper macro */
#define __PV_BIT(nr)		(1ULL << (63 - (nr)))

/* Plaintext control flags */
#define PV_PCF_ALLOW_DUMPING	__PV_BIT(34) /* dumping of the configuration is allowed */
#define PV_PCF_NO_DECRYPTION	__PV_BIT(35) /* prevent Ultravisor decryption during unpack operation */
#define PV_PCF_PCKMO_DEA_TDEA	__PV_BIT(56) /* PCKMO encrypt-DEA/TDEA-key functions allowed */
#define PV_PCF_PCKMO_AES	__PV_BIT(57) /* PCKMO encrypt-AES-key functions allowed */
#define PV_PCF_PCKM_ECC	__PV_BIT(58) /* PCKMO encrypt-ECC-key functions allowed */

/* Secret control flags */
#define PV_SCF_CCK_EXTENSION_SECRET_ENFORCMENT                                                     \
	__PV_BIT(1) /* All add-secret requests must provide an extension secret */

/* maxima for the PV version 1 */
#define PV_V1_IPIB_MAX_SIZE	PAGE_SIZE
#define PV_V1_PV_HDR_MAX_SIZE	(2 * PAGE_SIZE)

typedef struct pv_hdr_key_slot { // 32 32 16
	uint8_t digest_key[SHA256_DIGEST_LENGTH];
	uint8_t wrapped_key[32];
	uint8_t tag[AES_256_GCM_TAG_SIZE];
} __packed PvHdrKeySlot;

typedef struct pv_hdr_opt_item { // 4 32
	uint32_t otype;
	uint8_t ibk[32];
	uint8_t data[];
} __packed PvHdrOptItem;

/* integrity protected data (by GCM tag), but non-encrypted */
struct pv_hdr_head {// 8 4 4 12 4 8 8 8 8 160 64 64 64
	uint64_t magic; //8
	uint32_t version; //4
	uint32_t phs; //4
	uint8_t iv[AES_256_GCM_IV_SIZE]; //12
	uint32_t res1; //4
	uint64_t nks; //8
	uint64_t sea; //8
	uint64_t nep; //8
	uint64_t pcf; //8
	union ecdh_pub_key cust_pub_key; //160
	uint8_t pld[SHA512_DIGEST_LENGTH]; //64
	uint8_t ald[SHA512_DIGEST_LENGTH]; //64
	uint8_t tld[SHA512_DIGEST_LENGTH]; //64
} __packed;

/* Must not have any padding */
struct pv_hdr_encrypted { // 32 32 32 8 8 4 4
	uint8_t cust_comm_key[32]; //32
	uint8_t img_enc_key_1[AES_256_XTS_KEY_SIZE / 2]; //32
	uint8_t img_enc_key_2[AES_256_XTS_KEY_SIZE / 2]; //32
	struct psw_t psw; //8
	uint64_t scf; //8
	uint32_t noi; //4
	uint32_t res2; //4
};
STATIC_ASSERT(sizeof(struct pv_hdr_encrypted) ==
	      32 + 32 + 32 + sizeof(struct psw_t) + 8 + 4 + 4)

typedef struct pv_hdr {
	struct pv_hdr_head head;
	struct pv_hdr_key_slot *slots;
	struct pv_hdr_encrypted *encrypted;
	struct pv_hdr_opt_item **optional_items;
	uint8_t tag[AES_256_GCM_TAG_SIZE];
} PvHdr;

#endif
