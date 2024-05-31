#include "app_rsa.h"

#include "stm32f10x.h"

// ###########################################################################
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"

#define RSA512_test 2
#if RSA512_test == 0
// const char *my_public_key = "-----BEGIN PUBLIC KEY-----\n"
//                      "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAPARTRT+cgRRYkHFwQDqfXS1SFjARKoO"
//                     "BvLrxYzuEf/F0SDYBhXpDyD7H788l/OgbETwWbgScAGlqUhOgCpmbrcCAwEAAQ==\n"
//                      "-----END PUBLIC KEY-----";

// const char *my_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
//                       "MIIBOgIBAAJBAPARTRT+cgRRYkHFwQDqfXS1SFjARKoOBvLrxYzuEf/F0SDYBhXp"
//                         "DyD7H788l/OgbETwWbgScAGlqUhOgCpmbrcCAwEAAQJBALWAjyO5QGDNWxlZNxPH"
//                         "NfTf/oPDUea0VkKhSSnE8OzLns2vz4VIBQIEJgc+Fln9Vd40qVDzxVTLJuRzFWaO"
//                         "F6ECIQD/KKQUx3xZwH7XuijonKfwVdT+EsUwISmLemgxkbhX5wIhAPDb7EPng3H6"
//                         "dwWAwnUrJi2kRWQJzAFnktCfWpUKLBixAiBoJq+rJ65TeGaOKhfOszs9t9tkBkdl"
//                         "GPQ7UbC8Iw4LGwIgDA7mkCu5/+3LIaJlmdoUKjrMIor/BJ770af4r/d3Z7ECIFwY"
//                         "ksCpbZBTqk+P3J7+3dywkxuZVIEDuZEk+xuP0ixW\n"
//                       "-----END RSA PRIVATE KEY-----";

const char *my_public_key = "-----BEGIN PUBLIC KEY-----\n"
                            "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ1EhLpIAcKYx8nqrOvaE+kgn0JuZNyi8GeVv7gmPkVMvfUz1YE9fwekUlWPb8qQXHuJw5wUbhzxjC5IcFDXvSkCAwEAAQ==\n"
                            "-----END PUBLIC KEY-----";

const char *my_private_key = "-----BEGIN PRIVATE KEY-----\n"
                             "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAnUSEukgBwpjHyeqs69oT6S"
                             "CfQm5k3KLwZ5W/uCY+RUy99TPVgT1/B6RSVY9vypBce4nDnBRuHPGMLkhwUNe9KQIDAQAB"
                             "AkBjFmS6KdxSC4j1w5KoF4MsA43UgVGzYkYuPb/J+u6JIlAUf69dhvoYk634OO2m9wlOOu"
                             "3aa4o2qt9jEh5pRzIBAiEA0I0PV7IgTiWrS8BYEOGThAaluPJllJHobL2V51lOzJkCIQDB"
                             "DHynF4M3Yf+6/wQAGq47JhQAnGHR9zoWjNW9i2a/EQIgXT6Um4si8o3ZFtd7CKEzCZbHRf"
                             "fq/xB1sRjbC0Nc/hECIAS2iVSK/mkbu2KVV0OpYxeOlm5tYvX9Uy25wn4eKSQBAiAopCiv"
                             "HU7iaFs/xE7O6lOQ0599QB6Sr3C0woGhtWGGZg==\n"
                             "-----END PRIVATE KEY-----";
#elif RSA512_test == 1
const char *my_public_key = "-----BEGIN PUBLIC KEY-----\n"
                            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCh7XSXA6QA0zoFfATvpQyKzPqU"
                            "sKc9tKPccF1QQW6+5At3dzTrF6EpoUzC+ps7MZlz+qJN5wSSYdv4beh7Rrj2QRVB"
                            "a/HOJhg1Q4ttREBvrXp8pX48tDYjnjXlC4aBi6nylTLF630P7WGgX0ouQfDSySE8"
                            "/8TOcqOJ6eWFsF/xhwIDAQAB\n"
                            "-----END PUBLIC KEY-----";

const char *my_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
                             "MIICXQIBAAKBgQCh7XSXA6QA0zoFfATvpQyKzPqUsKc9tKPccF1QQW6+5At3dzTr"
                             "F6EpoUzC+ps7MZlz+qJN5wSSYdv4beh7Rrj2QRVBa/HOJhg1Q4ttREBvrXp8pX48"
                             "tDYjnjXlC4aBi6nylTLF630P7WGgX0ouQfDSySE8/8TOcqOJ6eWFsF/xhwIDAQAB"
                             "AoGATssPGpTI7yXZa+XHOR1lFv1bSZMULjCCM7fxkCXmz7iD4+P7uhHLeEhm49Gy"
                             "S4F9HDRvWdz6GojH0wEYSTRGt7bMqtJBbViZfw6i6XBPNVa5GZtc725PbZYrTEV2"
                             "W37oXrsRugTXYQiti+L9DsOzk4RFb9pCvVF1NKtVu/N7y0ECQQDXL7nbEyGOyQfa"
                             "TXBbZ0sTBtkTrJjI/xISghSNCDVDO25Eg1Ehc6G1X3k/9K3SHYr29d6V1d6yF4tC"
                             "hXjywIvxAkEAwKPFQjKInHTMJc+C9el1N4xYYSKdxpYZm9CQ1EVsPRkKu9WDqvV1"
                             "eati082EJ9CnXdujQsk57O9sazaRosOs9wJBAJL58yzyPTqEjsuJlxOnUrzVMZHh"
                             "kp2+sr5XgOfvUknwntlHBDQgAbSbWHrZiZv5N8CEoRqgcLIdqK2v8rOD1lECQFtK"
                             "AMOzENwb2VadtPD2Nk8hmgxGDEC8htw5BTkiwP1fLZ//ucq9UXNcDZRTkyoPDhFD"
                             "cWXH2ER43YcdL/zS/9cCQQCgzhDsn0SIfq/rIJk+b2193CQpPmwRZ72lRnO8/8fd"
                             "xRhCqWuK0VInolbnidE6aZvqDrlAFHAlFjhQaZVDOB05\n"
                             "-----END RSA PRIVATE KEY-----";
#elif RSA512_test == 2
const char *my_public_key = "-----BEGIN PUBLIC KEY-----\n"
                            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArU45wBhdiHuxbsgTOnRW"
                            "5PDP62yXrZvBBYVY5LxLzycAGjqoT4AU+8CqTv7QdAf58VHgInxiSFXN+vqa5bXw"
                            "3APBJqQGwVrKmNkyiLmi/yfxpVXStBv1orVRfIPZaw+NLP7dwRKInsgJXPqszdMX"
                            "mqs8l4jEGCDXPZIZpG39l/SHRw6hhC97rxjW3aj35lQuvJ27OcOhcHVQXxsy5W9x"
                            "gkXljpnO5eMZlx8DMbyKEA0ugXoceYh5baeS8UBmFM0uQ4OmTr44aloNfZie884u"
                            "aIAkGi8g/amEIVJzMoIjGYjRWz4ntS2DsuMx8nTVVoFe+z0eZVnsq6m6QXE6jEc3"
                            "UwIDAQAB\n"
                            "-----END PUBLIC KEY-----";

const char *my_private_key = "-----BEGIN RSA PRIVATE KEY-----\n"
                             "MIIEowIBAAKCAQEArU45wBhdiHuxbsgTOnRW5PDP62yXrZvBBYVY5LxLzycAGjqo"
                             "T4AU+8CqTv7QdAf58VHgInxiSFXN+vqa5bXw3APBJqQGwVrKmNkyiLmi/yfxpVXS"
                             "tBv1orVRfIPZaw+NLP7dwRKInsgJXPqszdMXmqs8l4jEGCDXPZIZpG39l/SHRw6h"
                             "hC97rxjW3aj35lQuvJ27OcOhcHVQXxsy5W9xgkXljpnO5eMZlx8DMbyKEA0ugXoc"
                             "eYh5baeS8UBmFM0uQ4OmTr44aloNfZie884uaIAkGi8g/amEIVJzMoIjGYjRWz4n"
                             "tS2DsuMx8nTVVoFe+z0eZVnsq6m6QXE6jEc3UwIDAQABAoIBAQCLLf+DHg4/xdbB"
                             "OTz3/OasBhl04EkPy75ASM8TI4VeX9vdNK5m6l3vsNMVjd6q0J0SCMcP6wSjQwWh"
                             "QhGT2YINr5Y3ChPCxL9f8U58L1mPwOx382y76Jhki2ldriW1rU+bizNcEx5VJiEe"
                             "4tJUmeqi9FI9AEE7f2RctjCRtSOsHAp8txl04Bgle5gyXzmcU0Hlp5bOmrafsOpd"
                             "vThlW6juDoDBMfdORRmSFLXn9FiJkCF1Yulvl4h/1R9s7K9SmMkq1Ptt89OO5OH7"
                             "4Zawes2wtLJyu7qZu/VGs5Vr1bDps5xQtW5TGha++NhGt7YHJcGNMEY8R8m7Cw1s"
                             "ba9lI/oBAoGBAN+RLQxDE5QeZoWqUbOwA5S0mNzPftp5JuJn3eN6k8mWB2vbV1Tf"
                             "hM614sgeJAmCJX0G4GHHnBQj5D5mY8YCe/jz5Dx9bd2knfPTFaOad4LxicCpchwf"
                             "cDn4ij4AYvDJTRvkQz24KHjc/veh/RGqYwX2xQBO/WaXb2ZnWplEm16zAoGBAMZy"
                             "cIO5iHuO429d87YC93ax8Gsg6ajWMdu+AJ33stiN2NgGDO6Ge6vt978K1GKGUGPS"
                             "wM1mPEfps50QWQtQzxG6Z8cxAFhE0XVgj+NUlYVkWd7LD64vZox9pO8KdKmUqCpV"
                             "n9OSmB6Y9TJq2ZqqO306297VbWvMw0FpCOob4RThAoGASwIGPyryEqvwccAnEUZo"
                             "rSe6cbscMGidZzC5/WxO0T+I1eMNdehYQpI7uDCEnrwPn9cCyUuTTh6MoXLw3qpO"
                             "tcP+O11J0yc752ZWyEE2/7PSJ9Wx90WE/a4pk4vFpkujl0wKU1bKHWLoGGU85wRn"
                             "nMSia+wUkKsWMSFUAEBIcIkCgYAR71fR39vA5voRH5meEoiQ9qX22KOlea5J4NMn"
                             "c7J7Nd6qL2nNyOO2dyxT3MOzH9Z2Hx8DsUCzcyCjik2x4xzDymgErZ4NXDLd+9sl"
                             "PYjB5H7mzs1c/bWz7ssQO46toNzN7q0iLvaGlWZbpyKBgu8bc01Zx0o7WucuqzJ+"
                             "DgT6oQKBgGHYhKM1FN5dRdLcHY8tDitwVK+IAdENws40esvewoK3affGdHXFUHXv"
                             "fxuQJFOXIijsTyL0r3kIhYmYofaYuJH7a79JU8vaWUzrm1nJK2luj4HwFvcGTHK7"
                             "affCq8rlj00Ie8/jjoom5MHOrqWci2qzsnCgCVFrGKQi1IbCVFA3\n"
                             "-----END RSA PRIVATE KEY-----";
#endif

const char aes_data[] = "{\"AESkey\":\"DPXlLYPp0/OSHQD5a1Qpew==\",\"CTEI\":\"183811950918001\"}";

static char buf[516];

static void dump_rsa_key(mbedtls_rsa_context *ctx)
{
    size_t olen;

    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
    mbedtls_mpi_write_string(&ctx->N, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("N: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->E, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("E: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->D, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("D: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->P, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("P: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->Q, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("Q: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->DP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DP: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->DQ, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("DQ: %s\n", buf);

    mbedtls_mpi_write_string(&ctx->QP, 16, buf, sizeof(buf), &olen);
    mbedtls_printf("QP: %s\n", buf);
    mbedtls_printf("\n  +++++++++++++++++ rsa keypair +++++++++++++++++\n\n");
}

static void dump_buf(uint8_t *buf, uint32_t len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ",
                       buf[i],
                       i == len - 1 ? "\r\n" : "");
    }
}

static int entropy_source(void *data, uint8_t *output, size_t len, size_t *olen)
{
    PUBLIC_GenerateRandVec(output, len);
    *olen = len;
    return 0;
}

int rsa_encrypt(unsigned char *plaintext, unsigned char *ciphertext, int msg_length, uint16_t len)
{

    mbedtls_printf("\nEncryption Begins.\n");
    mbedtls_printf("\nplaintext = %s\n", plaintext);

    unsigned char *pub_key = NULL;
    mbedtls_pk_context ctx_pk;

    /*********************************************/
    int ret = 1;

    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "rsa_encrypt";
    //    mbedtls_mpi N, E;       //定义一个大数，也就是公钥
    /*****************************************************/

    mbedtls_pk_init(&ctx_pk);

    if (0 != mbedtls_pk_parse_public_key(&ctx_pk, (unsigned char *)my_public_key, strlen(my_public_key) + 1))
    {
        mbedtls_printf("\n  . Can't import public key");
    }
    else
    {
        mbedtls_printf("\n  . Import public key successfully");
    }

    /*****************************************************************/

    mbedtls_printf("\n  . Seeding the random number generator ...");

    // memset(plaintext, 0, sizeof(plaintext));
    memset(ciphertext, 0, len);
    //    fflush(stdout);

    //    mbedtls_mpi_init(&N);
    //    mbedtls_mpi_init(&E);
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg); // 初始化ctr drbg结构体,用于随机数的生成
    mbedtls_entropy_init(&entropy);   // 初始化熵源

    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                               MBEDTLS_ENTROPY_MAX_GATHER,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)); // 生成随机数

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }
    /*导入pem内的公钥*/
    rsa = *(mbedtls_rsa_context *)ctx_pk.pk_ctx;

    /*
     * Calculate the RSA encryption of the hash.
     */
    mbedtls_printf("\n  . Generating the RSA encrypted value ...");
    //    fflush(stdout);
    /*加密操作，利用公钥加密*/
    ret = mbedtls_rsa_pkcs1_encrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, msg_length, plaintext, ciphertext);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("\n\nEncryption Done.\n");
    fflush(stdout);
exit:
    /*释放资源*/
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_pk_free(&ctx_pk);
    fflush(stdout);
    return 0;
}
static uint8_t output_buf[2048 / 8];
int rsa_decrypt(unsigned char *ciphertext, unsigned char *plaintext, uint16_t len)
{
    //    clock_t start, finish;
    double duration;
    //    start = clock();
    mbedtls_printf("Decryption Begins.\n");
    mbedtls_printf("\nciphertext = %s\n", ciphertext);

    FILE *f = NULL;
    char *str = NULL;
    long size;
    size_t n;
    unsigned char *priv_key = NULL;
    mbedtls_pk_context ctx_pk;
    /*******************************/
    int ret = 1;
    int c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP; // 定义大数
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    // unsigned char result[1024];
    // unsigned char buf[128];
    const char *pers = "rsa_decrypt";
    // memset(result, 0, sizeof(result));
    /*********************************/
    memset(plaintext, 0, len);
    mbedtls_pk_init(&ctx_pk);

    //    int length = strlen(my_private_key);
    //    priv_key = (unsigned char *)(malloc(length+1));

    //    strcpy((char*)priv_key, my_private_key);
    // if( ( ret = mbedtls_pk_parse_public_key( &pk, pub_key, length+1) ) != 0 )
    ret = mbedtls_pk_parse_key(&ctx_pk, (unsigned char *)my_private_key, strlen(my_private_key) + 1, NULL, 0);
    if (0 != ret)
    {
        mbedtls_printf("\n  . Can't import private key, %d", ret);
    }
    else
    {
        mbedtls_printf("\n  . Import private key successfully");
    }

    //    free(priv_key);
    //    priv_key = NULL;

    mbedtls_printf("\n  . Seeding the random number generator ...");
    fflush(stdout);

    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_mpi_init(&N);
    mbedtls_mpi_init(&P);
    mbedtls_mpi_init(&Q);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&DP);
    mbedtls_mpi_init(&DQ);
    mbedtls_mpi_init(&QP);

    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                               MBEDTLS_ENTROPY_MAX_GATHER,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                &entropy, (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit;
    }

    /*导入pem内的私钥*/
    rsa = *(mbedtls_rsa_context *)ctx_pk.pk_ctx;

    if ((ret = mbedtls_rsa_complete(&rsa)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_complete returned %d\n\n", ret);
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the plaintext.
     */
    mbedtls_printf("\n  . Decrypting the encrypted data ...");
    fflush(stdout);

    uint8_t test11[] = "oxjNWHp/XjabF3yJgpEOtIpUTOKeJxpeWDVgcFZO7EbYLC6kbSQ1Cz/t2CghLIngaAxUUdsnVMZEJbepxKtj2g==";

    uint8_t rst2[512];
    memset(rst2, 0, sizeof(rst2));
    uint32_t len2 = sizeof(output_buf);
    mbedtls_base64_encode(rst2, sizeof(rst2), &len2, output_buf, rsa.len);
    for (uint16_t i = 0; i < sizeof(rst2); i++)
    {
        mbedtls_printf("%x", rst2[i]);
    }
    mbedtls_printf("ok!!!!!!!!!!\n");

    ret = mbedtls_rsa_pkcs1_decrypt(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i, ciphertext, plaintext, 512);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_decrypt returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf("\n\nThe decrypted result is: '%s'\n", plaintext);
    mbedtls_printf("\nDecryption Done.\n");

    /* shwo RSA keypair */
    dump_rsa_key(&rsa);

    /* 4. sign */
    mbedtls_printf("\n  . RSA pkcs1 sign...");

    // 计算 SHA1 摘要
    unsigned char hash[20];
    mbedtls_sha1((const uint8_t *)aes_data, strlen(aes_data), hash);

    ret = mbedtls_rsa_pkcs1_sign(&rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, strlen(aes_data), hash, output_buf);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    for (uint16_t i = 0; i < sizeof(output_buf); i++)
    {
        mbedtls_printf("%x", output_buf[i]);
    }
    mbedtls_printf("ok!!!!!!!!!!\n");
    mbedtls_printf("%s\n", output_buf);

    /* show sign result */
    dump_buf(output_buf, sizeof(output_buf));

    uint8_t rst[512];
    memset(rst, 0, sizeof(rst));
    uint32_t len1 = sizeof(output_buf);
    mbedtls_base64_encode(rst, sizeof(rst), &len1, output_buf, rsa.len);
    mbedtls_printf("############## base64 encode : %s\n", rst);

    /* 5. verify sign*/
    mbedtls_printf("\n  . RSA pkcs1 verify...");

    ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, strlen(aes_data), hash, output_buf);

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");
    fflush(stdout);
exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&rsa);
    mbedtls_mpi_free(&N);
    mbedtls_mpi_free(&P);
    mbedtls_mpi_free(&Q);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&DP);
    mbedtls_mpi_free(&DQ);
    mbedtls_mpi_free(&QP);
    mbedtls_pk_free(&ctx_pk);

    fflush(stdout);
    return 0;
}

void setup()
{
    mbedtls_printf("Welcome to test the RSA demo!\n");
}

int mbedtls_rsa_sign_test(void)
{
    int ret;
    const char *msg = "HelloWorld";

    const char *pers = "rsa_sign_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context ctx;

    /* 1. init structure */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    /**
     * padding 是你想要使用的填充模式。在你的例子中，MBEDTLS_RSA_PKCS_V15 表示你想用 PKCS#1 v1.5 标准进行填充。
     * hash_id 是你在 RSA 使用的填充模式需要一个 hash 算法时，指定使用的 hash 算法的标识符。在你的例子中，0 表示不使用 hash。
     */
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    /* 2. update seed with we own interface ported */
    mbedtls_printf("\n  . Seeding the random number generator...");

    mbedtls_entropy_add_source(&entropy, entropy_source, NULL,
                               MBEDTLS_ENTROPY_MAX_GATHER,
                               MBEDTLS_ENTROPY_SOURCE_STRONG);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers,
                                strlen(pers));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    /* 3. generate an RSA keypair */
    mbedtls_printf("\n  . Generate RSA keypair...");

    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 512, 65537);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_gen_key returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    /* shwo RSA keypair */
    dump_rsa_key(&ctx);

    /* 4. sign */
    mbedtls_printf("\n  . RSA pkcs1 sign...");

    ret = mbedtls_rsa_pkcs1_sign(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, strlen(msg), (uint8_t *)msg, output_buf);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

    /* show sign result */
    dump_buf(output_buf, sizeof(output_buf));

    /* 5. verify sign*/
    mbedtls_printf("\n  . RSA pkcs1 verify...");

    ret = mbedtls_rsa_pkcs1_verify(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, strlen(msg), (uint8_t *)msg, output_buf);

    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    mbedtls_printf(" ok\n");

exit:

    /* 5. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&ctx);

    return ret;
}

char *msg = "8888888888888888888888888888812399999999999999999999";
unsigned char plaintext[4096];
unsigned char ciphertext[4096];
void RSA_TEST()
{

    memcpy(plaintext, msg, strlen(msg));
    plaintext[strlen(msg)] = '\0';
    int msg_length = strlen(msg) + 1;

    uint32_t cnt = 0;
    for (uint16_t i = 0; i < 100000; i++)
    {
        // 加密
        rsa_encrypt(plaintext, ciphertext, strlen(msg) + 1, sizeof(ciphertext));
        // 解密
        rsa_decrypt(ciphertext, plaintext, sizeof(plaintext));
        //		HAL_Delay(1000);
        // 签名测试
        mbedtls_rsa_sign_test();
        mbedtls_printf("cnt = %d\n", cnt++);
    }

    //	mbedtls_rsa_sign_test();
}

const char *my_public_key1 = "-----BEGIN PUBLIC KEY-----\n"
                             "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ1EhLpIAcKYx8nqrOvaE+kgn0JuZNyi8GeVv7gmPkVMvfUz1YE9fwekUlWPb8qQXHuJw5wUbhzxjC5IcFDXvSkCAwEAAQ==\n"
                             "-----END PUBLIC KEY-----";

// const char *my_private_key1 = "-----BEGIN PRIVATE KEY-----\n"
//                       "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAnUSEukgBwpjHyeqs69oT6S"
//					"CfQm5k3KLwZ5W/uCY+RUy99TPVgT1/B6RSVY9vypBce4nDnBRuHPGMLkhwUNe9KQIDAQAB"
//					"AkBjFmS6KdxSC4j1w5KoF4MsA43UgVGzYkYuPb/J+u6JIlAUf69dhvoYk634OO2m9wlOOu"
//					"3aa4o2qt9jEh5pRzIBAiEA0I0PV7IgTiWrS8BYEOGThAaluPJllJHobL2V51lOzJkCIQDB"
//					"DHynF4M3Yf+6/wQAGq47JhQAnGHR9zoWjNW9i2a/EQIgXT6Um4si8o3ZFtd7CKEzCZbHRf"
//					"fq/xB1sRjbC0Nc/hECIAS2iVSK/mkbu2KVV0OpYxeOlm5tYvX9Uy25wn4eKSQBAiAopCiv"
//					"HU7iaFs/xE7O6lOQ0599QB6Sr3C0woGhtWGGZg==\n"
//                       "-----END PRIVATE KEY-----";
const char *my_private_key1 = "MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAnUSEukgBwpjHyeqs69oT6S"
                              "CfQm5k3KLwZ5W/uCY+RUy99TPVgT1/B6RSVY9vypBce4nDnBRuHPGMLkhwUNe9KQIDAQAB"
                              "AkBjFmS6KdxSC4j1w5KoF4MsA43UgVGzYkYuPb/J+u6JIlAUf69dhvoYk634OO2m9wlOOu"
                              "3aa4o2qt9jEh5pRzIBAiEA0I0PV7IgTiWrS8BYEOGThAaluPJllJHobL2V51lOzJkCIQDB"
                              "DHynF4M3Yf+6/wQAGq47JhQAnGHR9zoWjNW9i2a/EQIgXT6Um4si8o3ZFtd7CKEzCZbHRf"
                              "fq/xB1sRjbC0Nc/hECIAS2iVSK/mkbu2KVV0OpYxeOlm5tYvX9Uy25wn4eKSQBAiAopCiv"
                              "HU7iaFs/xE7O6lOQ0599QB6Sr3C0woGhtWGGZg==";
void RSA_TEST1()
{
    uint8_t rst2[512];
    memset(rst2, 0, sizeof(rst2));
    uint32_t len2 = sizeof(output_buf);
    int rst = mbedtls_base64_decode(rst2, sizeof(rst2), &len2, my_private_key1, strlen(my_private_key1));
    mbedtls_printf("rst=%d\n", rst);
    mbedtls_printf("len2=%d\n", len2);
    for (uint16_t i = 0; i < sizeof(rst2); i++)
    {
        mbedtls_printf("%x", rst2[i]);
    }
    mbedtls_printf("\nok!!!!!!!!!!\n");
}
