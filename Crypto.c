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
/* Key encapsulation mechanism */
/* #define ML_KEM_512 */
#define ML_KEM_768
/* #define ML_KEM_1024 */
/* #define HQC128 */
/* #define HQC192 */
/* #define HQC256 */

/* Digital signatures */
#define ML_DSA_44
/* #define ML_DSA_65 */
/* #define ML_DSA_87 */
/* #define SLH_DSA_SHA2_128FSIMPLE */
/* #define SLH_DSA_SHA2_128SSIMPLE */
/* #define SLH_DSA_SHA2_192FSIMPLE */
/* #define SLH_DSA_SHA2_192SSIMPLE */
/* #define SLH_DSA_SHA2_256FSIMPLE */
/* #define SLH_DSA_SHA2_256SSIMPLE */
/* #define SLH_DSA_SHAKE_128FSIMPLE */
/* #define SLH_DSA_SHAKE_128SSIMPLE */
/* #define SLH_DSA_SHAKE_192FSIMPLE */
/* #define SLH_DSA_SHAKE_192SSIMPLE */
/* #define SLH_DSA_SHAKE_256FSIMPLE */
/* #define SLH_DSA_SHAKE_256SSIMPLE */
/* #define FN_DSA_512 */
/* #define FN_DSA_1024 */

#if (defined ML_KEM_512)
        #include "FsmSw_CommonLib.h"
        #include "ML_KEM_512_api.h"
        #include "ML_KEM_512_params.h"
        #include "ML_KEM_512_indcpa.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        ML_KEM_512_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        ML_KEM_512_SECRETKEYBYTES
        #define CRYPTO_ENC_SSBYTES               ML_KEM_SSBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       ML_KEM_512_CIPHERTEXTBYTES
        #define ML_KEM_INDCPA_MSGBYTES           ML_KEM_512_INDCPA_MSGBYTES
        #define ML_KEM_INDCPA_BYTES              ML_KEM_512_INDCPA_BYTES
        #define crypto_kem_keypair               ML_KEM_512_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   ML_KEM_512_Crypto_Kem_Enc
        #define crypto_kem_dec                   ML_KEM_512_Crypto_Kem_Dec
        #define indcpa_enc                       ML_KEM_512_Indcpa_Enc
        #define indcpa_dec                       ML_KEM_512_Indcpa_Dec

#elif (defined ML_KEM_768)
        #include "FsmSw_CommonLib.h"
        #include "ML_KEM_768_api.h"
        #include "ML_KEM_768_params.h"
        #include "ML_KEM_768_indcpa.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        ML_KEM_768_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        ML_KEM_768_SECRETKEYBYTES
        #define CRYPTO_ENC_SSBYTES               ML_KEM_SSBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       ML_KEM_768_CIPHERTEXTBYTES
        #define ML_KEM_INDCPA_MSGBYTES           ML_KEM_768_INDCPA_MSGBYTES
        #define ML_KEM_INDCPA_BYTES              ML_KEM_768_INDCPA_BYTES
        #define crypto_kem_keypair               ML_KEM_768_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   ML_KEM_768_Crypto_Kem_Enc
        #define crypto_kem_dec                   ML_KEM_768_Crypto_Kem_Dec
        #define indcpa_enc                       ML_KEM_768_Indcpa_Enc
        #define indcpa_dec                       ML_KEM_768_Indcpa_Dec

#elif (defined ML_KEM_1024)
        #include "FsmSw_CommonLib.h"
        #include "ML_KEM_1024_api.h"
        #include "ML_KEM_1024_params.h"
        #include "ML_KEM_1024_indcpa.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        ML_KEM_1024_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        ML_KEM_1024_SECRETKEYBYTES
        #define CRYPTO_ENC_SSBYTES               ML_KEM_SSBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       ML_KEM_1024_CIPHERTEXTBYTES
        #define ML_KEM_INDCPA_MSGBYTES           ML_KEM_1024_INDCPA_MSGBYTES
        #define ML_KEM_INDCPA_BYTES              ML_KEM_1024_INDCPA_BYTES
        #define crypto_kem_keypair               ML_KEM_1024_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   ML_KEM_1024_Crypto_Kem_Enc
        #define crypto_kem_dec                   ML_KEM_1024_Crypto_Kem_Dec
        #define indcpa_enc                       ML_KEM_1024_Indcpa_Enc
        #define indcpa_dec                       ML_KEM_1024_Indcpa_Dec

#elif (defined HQC128)
        #include "FsmSw_CommonLib.h"
        #include "Hqc128_api.h"
        #include "Hqc128_parameters.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        HQC128_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        HQC128_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       HQC128_CRYPTO_CIPHERTEXTBYTES
        #define CRYPTO_ENC_SSBYTES               64
        #define crypto_kem_keypair               Hqc128_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   Hqc128_Crypto_Kem_Enc
        #define crypto_kem_dec                   Hqc128_Crypto_Kem_Dec

#elif (defined HQC192)
        #include "FsmSw_CommonLib.h"
        #include "Hqc192_api.h"
        #include "Hqc192_parameters.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        HQC192_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        HQC192_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       HQC192_CRYPTO_CIPHERTEXTBYTES
        #define CRYPTO_ENC_SSBYTES               64
        #define crypto_kem_keypair               Hqc192_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   Hqc192_Crypto_Kem_Enc
        #define crypto_kem_dec                   Hqc192_Crypto_Kem_Dec

#elif (defined HQC256)
        #include "FsmSw_CommonLib.h"
        #include "Hqc256_api.h"
        #include "Hqc256_parameters.h"
        #define CRYPTO_ENC_PUBLICKEYBYTES        HQC256_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_ENC_SECRETKEYBYTES        HQC256_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_ENC_CIPHERTEXTBYTES       HQC256_CRYPTO_CIPHERTEXTBYTES
        #define CRYPTO_ENC_SSBYTES               64
        #define crypto_kem_keypair               Hqc256_Crypto_Kem_KeyPair
        #define crypto_kem_enc                   Hqc256_Crypto_Kem_Enc
        #define crypto_kem_dec                   Hqc256_Crypto_Kem_Dec
#endif

#if (defined ML_DSA_44)
        #include "FsmSw_CommonLib.h"
        #include "ML_DSA_44_api.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_ML_DSA_44_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_ML_DSA_44_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_ML_DSA_44_CRYPTO_BYTES
        #define crypto_sign_keypair     ML_DSA_44_Crypto_Sign_KeyPair
        #define crypto_sign_signature   ML_DSA_44_Crypto_Sign_Signature
        #define crypto_sign_verify      ML_DSA_44_Crypto_Sign_Verify
        #define crypto_sign             ML_DSA_44_Crypto_Sign
        #define crypto_sign_open        ML_DSA_44_Crypto_Sign_Open

#elif (defined ML_DSA_65)
        #include "FsmSw_CommonLib.h"
        #include "ML_DSA_65_api.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_ML_DSA_65_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_ML_DSA_65_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_ML_DSA_65_CRYPTO_BYTES
        #define crypto_sign_keypair     ML_DSA_65_Crypto_Sign_KeyPair
        #define crypto_sign_signature   ML_DSA_65_Crypto_Sign_Signature
        #define crypto_sign_verify      ML_DSA_65_Crypto_Sign_Verify
        #define crypto_sign             ML_DSA_65_Crypto_Sign
        #define crypto_sign_open        ML_DSA_65_Crypto_Sign_Open

#elif (defined ML_DSA_87)
        #include "FsmSw_CommonLib.h"
        #include "ML_DSA_87_api.h"
        #define CRYPTO_PUBLICKEYBYTES   FSMSW_ML_DSA_87_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FSMSW_ML_DSA_87_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FSMSW_ML_DSA_87_CRYPTO_BYTES
        #define crypto_sign_keypair     ML_DSA_87_Crypto_Sign_KeyPair
        #define crypto_sign_signature   ML_DSA_87_Crypto_Sign_Signature
        #define crypto_sign_verify      ML_DSA_87_Crypto_Sign_Verify
        #define crypto_sign             ML_DSA_87_Crypto_Sign
        #define crypto_sign_open        ML_DSA_87_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_128FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_128fSimple_api.h"
        #include "SLH_DSA_SHA2_128fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_128FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_128FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_128FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_128fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_128fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_128fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_128fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_128fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_128SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_128sSimple_api.h"
        #include "SLH_DSA_SHA2_128sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_128SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_128SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_128SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_128sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_128sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_128sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_128sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_128sSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_192FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_192fSimple_api.h"
        #include "SLH_DSA_SHA2_192fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_192FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_192FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_192FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_192fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_192fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_192fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_192fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_192fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_192SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_192sSimple_api.h"
        #include "SLH_DSA_SHA2_192sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_192SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_192SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_192SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_192sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_192sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_192sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_192sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_192sSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_256FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_256fSimple_api.h"
        #include "SLH_DSA_SHA2_256fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_256FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_256FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_256FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_256fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_256fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_256fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_256fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_256fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHA2_256SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHA2_256sSimple_api.h"
        #include "SLH_DSA_SHA2_256sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHA2_256SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHA2_256SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHA2_256SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHA2_256sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHA2_256sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHA2_256sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHA2_256sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHA2_256sSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_128FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_128fSimple_api.h"
        #include "SLH_DSA_SHAKE_128fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_128FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_128FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_128FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_128fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_128fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_128fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_128SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_128sSimple_api.h"
        #include "SLH_DSA_SHAKE_128sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_128SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_128SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_128SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_128sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_128sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_128sSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_192FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_192fSimple_api.h"
        #include "SLH_DSA_SHAKE_192fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_192FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_192FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_192FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_192fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_192fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_192fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_192SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_192sSimple_api.h"
        #include "SLH_DSA_SHAKE_192sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_192SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_192SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_192SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_192sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_192sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_192sSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_256FSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_256fSimple_api.h"
        #include "SLH_DSA_SHAKE_256fSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_256FSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_256FSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_256FSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_256fSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_256fSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_256fSimple_Crypto_Sign_Open

#elif (defined SLH_DSA_SHAKE_256SSIMPLE)
        #include "FsmSw_CommonLib.h"
        #include "SLH_DSA_SHAKE_256sSimple_api.h"
        #include "SLH_DSA_SHAKE_256sSimple_params.h"
        #define CRYPTO_PUBLICKEYBYTES   SLH_DSA_SHAKE_256SSIMPLE_PK_BYTES
        #define CRYPTO_SECRETKEYBYTES   SLH_DSA_SHAKE_256SSIMPLE_SK_BYTES
        #define CRYPTO_BYTES            SLH_DSA_SHAKE_256SSIMPLE_BYTES
        #define crypto_sign_keypair     SLH_DSA_SHAKE_256sSimple_Crypto_Sign_KeyPair
        #define crypto_sign_signature   SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Signature
        #define crypto_sign_verify      SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Verify
        #define crypto_sign             SLH_DSA_SHAKE_256sSimple_Crypto_Sign
        #define crypto_sign_open        SLH_DSA_SHAKE_256sSimple_Crypto_Sign_Open

#elif (defined FN_DSA_512)
        #include "FsmSw_CommonLib.h"
        #include "FN_DSA_512_api.h"
        #define CRYPTO_PUBLICKEYBYTES   FN_DSA_512_CRYPTO_PUBLICKEYBYTES
        #define CRYPTO_SECRETKEYBYTES   FN_DSA_512_CRYPTO_SECRETKEYBYTES
        #define CRYPTO_BYTES            FN_DSA_512_CRYPTO_BYTES
        #define crypto_sign_keypair     FN_DSA_512_Crypto_Sign_KeyPair
        #define crypto_sign_signature   FN_DSA_512_Crypto_Sign_Signature
        #define crypto_sign_verify      FN_DSA_512_Crypto_Sign_Verify
        #define crypto_sign             FN_DSA_512_Crypto_Sign
        #define crypto_sign_open        FN_DSA_512_Crypto_Sign_Open

#elif (defined FN_DSA_1024)
       #include "FsmSw_CommonLib.h"
       #include "FN_DSA_1024_api.h"
       #define CRYPTO_PUBLICKEYBYTES   FN_DSA_1024_CRYPTO_PUBLICKEYBYTES
       #define CRYPTO_SECRETKEYBYTES   FN_DSA_1024_CRYPTO_SECRETKEYBYTES
       #define CRYPTO_BYTES            FN_DSA_1024_CRYPTO_BYTES
       #define crypto_sign_keypair     FN_DSA_1024_Crypto_Sign_KeyPair
       #define crypto_sign_signature   FN_DSA_1024_Crypto_Sign_Signature
       #define crypto_sign_verify      FN_DSA_1024_Crypto_Sign_Verify
       #define crypto_sign             FN_DSA_1024_Crypto_Sign
       #define crypto_sign_open        FN_DSA_1024_Crypto_Sign_Open
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
* Name:        FsmSw_Crypto_KeyEncapsulationMechanismTest
*
* Description: Test function for key encapsulation mechanism.
*
* Arguments:   void
***********************************************************************************************************************/
void FsmSw_Crypto_KeyEncapsulationMechanismTest(void)
{
    /* public key alice */
    static uint8 pk_alice[CRYPTO_ENC_PUBLICKEYBYTES];
    /* secret key alice */
    static uint8 sk_alice[CRYPTO_ENC_SECRETKEYBYTES];
    /* public key bob */
    static uint8 pk_bob[CRYPTO_ENC_PUBLICKEYBYTES];
    /* secret key bob */
    static uint8 sk_bob[CRYPTO_ENC_SECRETKEYBYTES];
    /* shared key alice */
    static uint8 ss_alice[CRYPTO_ENC_SSBYTES];
    /* shared key bob */
    static uint8 ss_bob[CRYPTO_ENC_SSBYTES];
    /* cipher text */
    static uint8 ct[CRYPTO_ENC_CIPHERTEXTBYTES];
    
    #if defined(ML_KEM_512) || defined(ML_KEM_768) || defined(ML_KEM_1024)
    
    /* input message */
    static uint8 inMsg[ML_KEM_INDCPA_MSGBYTES];
    /* output message */
    static uint8 outMsg[ML_KEM_INDCPA_MSGBYTES];
    /* cipher message */
    static uint8 cipherMsg[ML_KEM_INDCPA_BYTES];
    /* coins */
    static uint8 coins[ML_KEM_SYMBYTES];
    
    #endif

    /* generate key pair for alice */
    (void) crypto_kem_keypair(pk_alice, sk_alice);

    /* generate key pair for bob */
    (void) crypto_kem_keypair(pk_bob, sk_bob);



    /* encapsulate */
    (void) crypto_kem_enc(ct, ss_alice, pk_bob);
    
    /* decapsulate */
    (void) crypto_kem_dec(ss_bob, ct, sk_bob);
    

    #if defined(ML_KEM_512) || defined(ML_KEM_768) || defined(ML_KEM_1024)

    /* generate message */
    (void) FsmSw_CommonLib_RandomBytes(inMsg, ML_KEM_INDCPA_MSGBYTES);
    /* generate coins */
    (void) FsmSw_CommonLib_RandomBytes(coins, ML_KEM_INDCPA_MSGBYTES);

    /* encrypt */
    indcpa_enc(cipherMsg, inMsg, pk_bob, coins);

    /* decrypt */
    indcpa_dec(outMsg, cipherMsg, sk_bob);
    
    #endif
}

/***********************************************************************************************************************
* Name:        FsmSw_Crypto_DigitalSignatureTest
*
* Description: Test function for digital signatures.
*
* Arguments:   void
***********************************************************************************************************************/
void FsmSw_Crypto_DigitalSignatureTest(void)
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
