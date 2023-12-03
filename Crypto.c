/***********************************************************************************************************************
*
*                                          IAV GmbH
*                          All rights reserved - Alle Rechte vorbehalten
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
    crypto_kem_keypair(pk_alice, sk_alice);

    /* generate key pair for bob */
    crypto_kem_keypair(pk_bob, sk_bob);

    /* encapsulate */
    crypto_kem_enc(ct, ss_alice, pk_bob);

    /* decapsulate */
    crypto_kem_dec(ss_bob, ct, sk_bob);


    /* generate message */
    FsmSw_CommonLib_randombytes(inMsg, KYBER_INDCPA_MSGBYTES);
    /* generate coins */
    FsmSw_CommonLib_randombytes(coins, KYBER_INDCPA_MSGBYTES);

    /* encrypt */
    indcpa_enc(cipherMsg, inMsg, pk_bob, coins);

    /* decrypt */
    indcpa_dec(outMsg, cipherMsg, sk_bob);
}
