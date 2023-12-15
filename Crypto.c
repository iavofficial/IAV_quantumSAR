/***********************************************************************************************************************
*
*                                          IAV GmbH
*
***********************************************************************************************************************/
/*
 *
 *  $File$
 *
 *  $Author$
 *
 *  $Date$
 *
 *  $Rev$
 *
 **********************************************************************************************************************/

/**********************************************************************************************************************/
/* INCLUDES                                                                                                           */
/**********************************************************************************************************************/
#include "Crypto.h"

/**********************************************************************************************************************/
/* DEFINES                                                                                                            */
/**********************************************************************************************************************/
#define KYBER512
/* #define KYBER768 */
/* #define KYBER1024 */

#define DILITHIUM2
/* #define DILITHIUM3 */
/* #define DILITHIUM5 */

#if (defined KYBER512)
        #include "FsmSw_CommonLib.h"
        #include "FsmSw_Kyber512_kem.h"
        #include "FsmSw_Kyber512_params.h"
        #include "FsmSw_Kyber512_indcpa.h"
        #define KYBER_PUBLICKEYBYTES        KYBER512_PUBLICKEYBYTES
        #define KYBER_SECRETKEYBYTES        KYBER512_SECRETKEYBYTES
        #define KYBER_INDCPA_MSGBYTES       KYBER512_INDCPA_MSGBYTES
        #define KYBER_CIPHERTEXTBYTES       KYBER512_CIPHERTEXTBYTES
        #define KYBER_INDCPA_BYTES          KYBER512_INDCPA_BYTES
        #define crypto_kem_keypair          FsmSw_Kyber512_crypto_kem_keypair
        #define crypto_kem_enc              FsmSw_Kyber512_crypto_kem_enc
        #define crypto_kem_dec              FsmSw_Kyber512_crypto_kem_dec
        #define indcpa_enc                  FsmSw_Kyber512_indcpa_enc
        #define indcpa_dec                  FsmSw_Kyber512_indcpa_dec

#elif (defined KYBER768)
        #include "FsmSw_CommonLib.h"
        #include "FsmSw_Kyber768_kem.h"
        #include "FsmSw_Kyber768_params.h"
        #include "FsmSw_Kyber768_indcpa.h"
        #define KYBER_PUBLICKEYBYTES        KYBER768_PUBLICKEYBYTES
        #define KYBER_SECRETKEYBYTES        KYBER768_SECRETKEYBYTES
        #define KYBER_INDCPA_MSGBYTES       KYBER768_INDCPA_MSGBYTES
        #define KYBER_CIPHERTEXTBYTES       KYBER768_CIPHERTEXTBYTES
        #define KYBER_INDCPA_BYTES          KYBER768_INDCPA_BYTES
        #define crypto_kem_keypair          FsmSw_Kyber768_crypto_kem_keypair
        #define crypto_kem_enc              FsmSw_Kyber768_crypto_kem_enc
        #define crypto_kem_dec              FsmSw_Kyber768_crypto_kem_dec
        #define indcpa_enc                  FsmSw_Kyber768_indcpa_enc
        #define indcpa_dec                  FsmSw_Kyber768_indcpa_dec

#elif (defined KYBER1024)
        #include "FsmSw_CommonLib.h"
        #include "FsmSw_Kyber1024_kem.h"
        #include "FsmSw_Kyber1024_params.h"
        #include "FsmSw_Kyber1024_indcpa.h"
        #define KYBER_PUBLICKEYBYTES        KYBER1024_PUBLICKEYBYTES
        #define KYBER_SECRETKEYBYTES        KYBER1024_SECRETKEYBYTES
        #define KYBER_INDCPA_MSGBYTES       KYBER1024_INDCPA_MSGBYTES
        #define KYBER_CIPHERTEXTBYTES       KYBER1024_CIPHERTEXTBYTES
        #define KYBER_INDCPA_BYTES          KYBER1024_INDCPA_BYTES
        #define crypto_kem_keypair          FsmSw_Kyber1024_crypto_kem_keypair
        #define crypto_kem_enc              FsmSw_Kyber1024_crypto_kem_enc
        #define crypto_kem_dec              FsmSw_Kyber1024_crypto_kem_dec
        #define indcpa_enc                  FsmSw_Kyber1024_indcpa_enc
        #define indcpa_dec                  FsmSw_Kyber1024_indcpa_dec
#endif

#if (defined DILITHIUM2)
    #include "FsmSw_CommonLib.h"
    #include "FsmSw_Dilithium2_sign.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_DILITHIUM2_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_DILITHIUM2_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_DILITHIUM2_CRYPTO_BYTES
        #define crypto_sign_keypair     FsmSw_Dilithium2_crypto_sign_keypair
        #define crypto_sign_signature   FsmSw_Dilithium2_crypto_sign_signature
        #define crypto_sign_verify      FsmSw_Dilithium2_crypto_sign_verify
        #define crypto_sign             FsmSw_Dilithium2_crypto_sign
        #define crypto_sign_open        FsmSw_Dilithium2_crypto_sign_open

#elif (defined DILITHIUM3)
        #include "FsmSw_CommonLib.h"
        #include "FsmSw_Dilithium3_sign.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_DILITHIUM3_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_DILITHIUM3_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_DILITHIUM3_CRYPTO_BYTES
        #define crypto_sign_keypair     FsmSw_Dilithium3_crypto_sign_keypair
        #define crypto_sign_signature   FsmSw_Dilithium3_crypto_sign_signature
        #define crypto_sign_verify      FsmSw_Dilithium3_crypto_sign_verify
        #define crypto_sign             FsmSw_Dilithium3_crypto_sign
        #define crypto_sign_open        FsmSw_Dilithium3_crypto_sign_open

#elif (defined DILITHIUM5)
        #include "FsmSw_CommonLib.h"
        #include "FsmSw_Dilithium5_sign.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_DILITHIUM5_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_DILITHIUM5_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_DILITHIUM5_CRYPTO_BYTES
        #define crypto_sign_keypair     FsmSw_Dilithium5_crypto_sign_keypair
        #define crypto_sign_signature   FsmSw_Dilithium5_crypto_sign_signature
        #define crypto_sign_verify      FsmSw_Dilithium5_crypto_sign_verify
        #define crypto_sign             FsmSw_Dilithium5_crypto_sign
        #define crypto_sign_open        FsmSw_Dilithium5_crypto_sign_open
#endif

/**********************************************************************************************************************/
/* TYPES                                                                                                              */
/**********************************************************************************************************************/

/**********************************************************************************************************************/
/* GLOBAL VARIABLES                                                                                                   */
/**********************************************************************************************************************/

/**********************************************************************************************************************/
/* MACROS                                                                                                             */
/**********************************************************************************************************************/

/**********************************************************************************************************************/
/* PRIVATE FUNCTION PROTOTYPES                                                                                        */
/**********************************************************************************************************************/

/**********************************************************************************************************************/
/* PRIVATE FUNCTIONS DEFINITIONS                                                                                      */
/**********************************************************************************************************************/

/**********************************************************************************************************************/
/* PUBLIC FUNCTIONS DEFINITIONS                                                                                       */
/**********************************************************************************************************************/
/***********************************************************************************************************************
* Name:        FsmSw_Crypto_KyberTest
*
* Description: Test function for Kyber.
*
* Arguments:   void
***********************************************************************************************************************/
void FsmSw_Crypto_KyberTest(void)
{
    /* public key alice */
    static uint8 pk_alice[KYBER_PUBLICKEYBYTES];
    /* secret key alice */
    static uint8 sk_alice[KYBER_SECRETKEYBYTES];
    /* public key bob */
    static uint8 pk_bob[KYBER_PUBLICKEYBYTES];
    /* secret key bob */
    static uint8 sk_bob[KYBER_SECRETKEYBYTES];
    /* shared key alice */
    static uint8 ss_alice[KYBER_SSBYTES];
    /* shared key bob */
    static uint8 ss_bob[KYBER_SSBYTES];
    /* input message */
    static uint8 inMsg[KYBER_INDCPA_MSGBYTES];
    /* output message */
    static uint8 outMsg[KYBER_INDCPA_MSGBYTES];
    /* cipher text */
    static uint8 ct[KYBER_CIPHERTEXTBYTES];
    /* cipher message */
    static uint8 cipherMsg[KYBER_INDCPA_BYTES];
    /* coins */
    static uint8 coins[KYBER_SYMBYTES];

    /* generate key pair for alice */
    (void) crypto_kem_keypair(pk_alice, sk_alice);

    /* generate key pair for bob */
    (void) crypto_kem_keypair(pk_bob, sk_bob);

    /* encapsulate */
    (void) crypto_kem_enc(ct, ss_alice, pk_bob);

    /* decapsulate */
    (void) crypto_kem_dec(ss_bob, ct, sk_bob);

    /* generate message */
    (void) FsmSw_CommonLib_randombytes(inMsg, KYBER_INDCPA_MSGBYTES);
    /* generate coins */
    (void) FsmSw_CommonLib_randombytes(coins, KYBER_INDCPA_MSGBYTES);

    /* encrypt */
    indcpa_enc(cipherMsg, inMsg, pk_bob, coins);

    /* decrypt */
    indcpa_dec(outMsg, cipherMsg, sk_bob);
}

/***********************************************************************************************************************
* Name:        FsmSw_Crypto_DilithiumTest
*
* Description: Test function for Dilithium.
*
* Arguments:   void
***********************************************************************************************************************/
void FsmSw_Crypto_DilithiumTest(void)
{
    /* public key */
    static uint8  pk[CRYPTO_PUBLICKEYBYTES];
    /* secret key */
    static uint8  sk[CRYPTO_SECRETKEYBYTES];

    /* signature */
    static uint8  sig[CRYPTO_BYTES];
    /* signature length */
    static uint32 siglen;
    /* message */
    static uint8  m[] = { "IAV quantumSAR" };
    /* message length */
    static uint32 mlen = sizeof(m);
    /* signature message */
    static uint8  sm[CRYPTO_BYTES + sizeof(m)];
    /* signature message length */
    static uint32 smlen;
    /* output message */
    static uint8  mout[sizeof(m)];
    /* output message length */
    static uint32 moutlen;

    /* generate key pair */
    (void) crypto_sign_keypair(pk, sk);

    /* calculate signature */
    (void) crypto_sign_signature(sig, &siglen, m, mlen, sk);

    /* verifies signature */
    (void) crypto_sign_verify(sig, siglen, m, mlen, pk);

    /* signed message */
    (void) crypto_sign(sm, &smlen, m, mlen, sk);

    /* verify signed message */
    (void) crypto_sign_open(mout, &moutlen, sm, smlen, pk);
}
