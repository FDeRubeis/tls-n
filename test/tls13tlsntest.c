#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/time.h>

#include "../ssl/packet_locl.h"

#include "ssltestlib.h"
#include "testutil.h"

/*in the first round, several short messages are
 * sent. In the second, some long ones.
 */
#define MAX_RECORD_LEN 16384
#define LENGTH_FIRST_ROUND 50
#define NUMBER_FIRST_ROUND 40000
#define LENGTH_SECOND_ROUND 40000
#define NUMBER_SECOND_ROUND 8
#define LENGTH_BIG_MESSAGE 100000
#define MAX_DURATION (10 * 60 * 1e6) /*10 minutes */

static int tlsn_create_and_connect(SSL_CTX **serverctx_ptr,
                                   SSL_CTX **clientctx_ptr, SSL **serverssl_ptr,
                                   SSL **clientssl_ptr)
{

    char *server_cert, *pkey, *trusted_cert;

    if (!TEST_ptr(server_cert = test_get_argument(0))
        || !TEST_ptr(pkey = test_get_argument(1))
        || !TEST_ptr(trusted_cert = test_get_argument(2))) {
        TEST_perror("Could not parse the input correctly");
        return 0;
    }

    if (!TEST_int_gt
        (create_ssl_ctx_pair
         (TLS_server_method(), TLS_client_method(), serverctx_ptr,
          clientctx_ptr, server_cert, pkey), 0)) {
        TEST_perror("Failed to create SSL_CTX pair");
        return 0;
    }

    size_t chunk_size = rand() % (LENGTH_FIRST_ROUND / 3); /*when chunk size is 0, it counts as MAX_RECORD_LEN */
    if (!TEST_int_gt(SSL_CTX_set_chunk_size(*clientctx_ptr, chunk_size), 0)) {
        TEST_perror("Error setting chunk size");
        return 0;
    }
    size_t salt_size =
        rand() % (MAXIMUM_SALT_SIZE - MINIMUM_SALT_SIZE + 1) +
        MINIMUM_SALT_SIZE;
    if (!TEST_int_gt(SSL_CTX_set_salt_size(*clientctx_ptr, salt_size), 0)) {
        TEST_perror("Error setting salt size");
        return 0;
    }

    if (!TEST_int_gt(SSL_CTX_set_tlsn_extension_client(*clientctx_ptr), 0)) {
        TEST_perror("Error setting tlsn extension in client");
        return 0;
    }

    if (!TEST_int_gt(SSL_CTX_set_tlsn_extension_server(*serverctx_ptr), 0)) {
        TEST_perror("Error setting tlsn extension in server");
        return 0;
    }

    if (!TEST_int_gt
        (SSL_CTX_load_verify_locations(*clientctx_ptr, trusted_cert, NULL),
         0)) {
        TEST_perror("Error setting trust store");
        return 0;
    }

    SSL_CTX_set_verify(*clientctx_ptr, SSL_VERIFY_PEER, NULL);

    if (!TEST_int_gt
        (create_ssl_objects
         (*serverctx_ptr, *clientctx_ptr, serverssl_ptr, clientssl_ptr, NULL,
          NULL), 0)) {
        TEST_perror(" Create SSL objects failed");
        return 0;
    }

    if (!TEST_int_gt
        (create_ssl_connection(*serverssl_ptr, *clientssl_ptr, SSL_ERROR_NONE),
         0)) {
        printf("Certificate verification error: %ld\n",
               SSL_get_verify_result(*clientssl_ptr));
        TEST_perror("Create SSL connection failed");
        return 0;
    }

    if (!TEST_int_gt(SSL_version(*serverssl_ptr) == TLS1_3_VERSION, 0)) {
        TEST_perror("Version is not tls1.3");
        return 0;
    }

    TEST_info("Connection created-> Chunk size: %lu , Salt size: %lu \n",
              SSL_get_chunk_size(*clientssl_ptr),
              SSL_get_salt_size(*clientssl_ptr));

    return 1;
}

static int exchange_evidence(SSL *serverssl, SSL *clientssl, char *read_buffer)
{

    if (!TEST_int_gt
        (SSL_tlsn_request_evidence(clientssl, INCLUDE_CERT_CHAIN), 0)) {
        TEST_perror("Error requesting evidence");
        return 0;
    }

    int p = 0;
    int prv_sent_resp = SSL_get_tlsn_sent_responses(serverssl);
    if (!TEST_int_gt(p = SSL_read(serverssl, read_buffer, MAX_RECORD_LEN) == -1
                     && SSL_get_tlsn_sent_responses(serverssl) ==
                     prv_sent_resp + 1, 0)) {
        TEST_perror("Error reading request");
        return 0;
    }

    if (!TEST_int_gt(SSL_tlsn_receive_response(clientssl), -1)) {
        TEST_perror("Error reading evidence");
        return 0;
    }

    return 1;
}

static int send_message(SSL *sender, SSL *receiver,
                        uint16_t **message_chunks,
                        size_t *curr_num_messages_ptr, char *message,
                        size_t len, char *read_buffer)
{
    if (!TEST_int_gt(SSL_write(sender, message, len), 0)) {
        TEST_error("Error writing message: %*s", (int)len, message);
        return 0;
    }

    int p = 0;
    uint32_t i;
    for (i = 0; i < len / 16384 + 1; i++) {
        if (!TEST_int_gt
            (p = SSL_read(receiver, read_buffer, MAX_RECORD_LEN), 0)) {
            TEST_error("Error reading message: %*s", (int)len, message);
        } else {
            (*curr_num_messages_ptr)++;
            *message_chunks =
                OPENSSL_realloc(*message_chunks,
                                *curr_num_messages_ptr * sizeof(uint16_t));
            /*chunk size must be the same for sender and receiver */
            (*message_chunks)[*curr_num_messages_ptr - 1] =
                (p - 1) / SSL_get_chunk_size(receiver) + 1;
        }
    }

    return 1;
}

static int exchange_messages(SSL *serverssl, SSL *clientssl,
                             char *message, char *read_buffer,
                             uint16_t **message_chunks,
                             size_t *curr_num_messages_ptr, int max_number,
                             int max_length)
{
    int num_messages = rand() % max_number + 1;
    //int num_messages = max_number;
    int i, coin_toss;
    int message_len;
    SSL *sender, *receiver;
    for (i = 0; i < num_messages; i++) {
        coin_toss = rand() % 2;
        sender = coin_toss ? serverssl : clientssl;
        receiver = coin_toss ? clientssl : serverssl;

        message_len = rand() % max_length + 1;
        if (!TEST_int_gt(RAND_bytes((unsigned char *)message, message_len), 0)) {
            TEST_error("message number: %d could not be assigned", i);
            return 0;
        }

        if (!TEST_int_gt(send_message(sender, receiver,
                                      message_chunks, curr_num_messages_ptr,
                                      message, message_len, read_buffer), 0)) {
            TEST_error("Error sending message: %*s", (int)message_len, message);
            return 0;
        }
    }
    return 1;
}

static void free_sens_mtrx(int16_t **sens_mtrx, size_t curr_num_messages)
{
    if (sens_mtrx == NULL)
        return;
    size_t i;
    for (i = 0; i < curr_num_messages; i++) {
        OPENSSL_free(sens_mtrx[i]);
        sens_mtrx[i] = NULL;
    }

    OPENSSL_free(sens_mtrx);
}

static int append_rand(int16_t *array, size_t index, uint16_t maximum)
{
    int is_present = 1;
    int16_t number;
    size_t i;

    if (index >= maximum)
        return 0;

    while (is_present) {
        number = rand() % maximum;
        is_present = 0;

        for (i = 0; i < index; i++) {
            if (array[i] == number)
                is_present = 1;
        }
    }

    array[index] = number;
    return 1;
}

static int16_t **extend_sens_mtrx(int16_t **sens_mtrx, size_t prev_num_messages,
                                  uint16_t *message_chunks,
                                  size_t curr_num_messages)
{

    size_t i, k;
    int not_hidden;
    uint16_t num_hidden_chunks;
    if (!TEST_ptr
        (sens_mtrx =
         (int16_t **)OPENSSL_realloc(sens_mtrx,
                                     curr_num_messages * sizeof(int16_t *))))
        return NULL;

    for (i = prev_num_messages; i < curr_num_messages; i++) {
        if (!TEST_ptr
            (sens_mtrx[i] =
             (int16_t *)OPENSSL_malloc((message_chunks[i] + 1) *
                                       sizeof(int16_t))))
            return NULL;
    }

    for (i = prev_num_messages; i < curr_num_messages; i++) {
        not_hidden = rand() % 4; //one fourth of message is hidden
        if (not_hidden) {
            num_hidden_chunks = rand() % message_chunks[i];
            for (k = 0; k < num_hidden_chunks; k++) {
                if (!TEST_int_gt
                    (append_rand(sens_mtrx[i], k, message_chunks[i]), 0))
                    return NULL;
            }
            sens_mtrx[i][k] = -1;
        } else {
            sens_mtrx[i][0] = -2;
        }
    }

    return sens_mtrx;
}

/*returns microseconds since epoch*/
static uint64_t get_micro_time()
{
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return (uint64_t)currentTime.tv_sec * (uint64_t)1e6 + currentTime.tv_usec;
}

static int tlsn_robustness(void)
{
    int testresult = 0;
    char *read_buffer = OPENSSL_malloc(MAX_RECORD_LEN);
    char *message = OPENSSL_malloc(LENGTH_BIG_MESSAGE);
    uint16_t *message_chunks = NULL;
    size_t curr_num_messages = 0;
    size_t prev_num_messages = 0;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CTX *serverctx = NULL;
    SSL_CTX *clientctx = NULL;
    int16_t **sens_mtrx = NULL;
    unsigned char *proof_str;
    uint64_t proof_len;
    srand(time(NULL));

    int big_message_len = LENGTH_BIG_MESSAGE;
    char big_message[big_message_len];

    if (!TEST_int_gt
        (tlsn_create_and_connect
         (&serverctx, &clientctx, &serverssl, &clientssl), 0))
        goto end;

    if (!TEST_int_gt
        (exchange_messages
         (serverssl, clientssl, message, read_buffer, &message_chunks,
          &curr_num_messages, NUMBER_FIRST_ROUND, LENGTH_FIRST_ROUND), 0)) {
        goto end;
    }

    if (!TEST_int_gt(exchange_evidence(serverssl, clientssl, read_buffer), 0))
        goto end;

    if (!TEST_ptr
        (sens_mtrx =
         extend_sens_mtrx(sens_mtrx, prev_num_messages, message_chunks,
                          curr_num_messages))) {
        TEST_perror("Error creating sensitive matrix");
        goto end;
    }

    if (!TEST_int_gt
        (SSL_tlsn_hide_sensitive_chunks
         (clientssl, INCLUDE_CERT_CHAIN, sens_mtrx, curr_num_messages), 0)) {
        TEST_perror("Error hiding chunks");
        goto end;
    }

    if (!TEST_int_gt
        (SSL_tls_get_proof_string(clientssl, &proof_str, &proof_len), 0)) {
        TEST_perror("Error parsing proof");
        goto end;
    }

    uint64_t now = get_micro_time(); /*in microseconds */
    if (!TEST_int_gt
        (SSL_tlsn_verify_with_certchain
         (clientssl, proof_str, proof_len, now - MAX_DURATION, now,
          now - MAX_DURATION, now, MAX_DURATION), 0)) {
        TEST_perror("Error reading evidence");
        goto end;
    } else {
        TEST_info("First evidence verified successfully\n");
    }

    free_sens_mtrx(sens_mtrx, curr_num_messages);
    sens_mtrx = NULL;

    if (!TEST_ptr
        (sens_mtrx =
         extend_sens_mtrx(sens_mtrx, prev_num_messages, message_chunks,
                          curr_num_messages))) {
        TEST_perror("Error creating sensitive matrix");
        goto end;
    }

    if (!TEST_int_gt
        (SSL_tlsn_hide_sensitive_chunks
         (clientssl, INCLUDE_CERT_CHAIN, sens_mtrx, curr_num_messages), 0)) {
        TEST_perror("Error hiding chunks");
        goto end;
    }

    if (!TEST_int_gt
        (SSL_tls_get_proof_string(clientssl, &proof_str, &proof_len), 0)) {
        TEST_perror("Error parsing proof");
        goto end;
    }

    now = get_micro_time();     //in microseconds
    if (!TEST_int_gt
        (SSL_tlsn_verify_with_certchain
         (clientssl, proof_str, proof_len, now - MAX_DURATION, now,
          now - MAX_DURATION, now, MAX_DURATION), 0)) {
        TEST_perror("Error reading evidence");
        goto end;
    } else {
        TEST_info("Second evidence verified successfully\n");
    }
    prev_num_messages = curr_num_messages;

    if (!TEST_int_gt
        (exchange_messages
         (serverssl, clientssl, message, read_buffer, &message_chunks,
          &curr_num_messages, NUMBER_SECOND_ROUND, LENGTH_SECOND_ROUND), 0)) {
        goto end;
    }

    if (!TEST_int_gt
        (RAND_bytes((unsigned char *)big_message, big_message_len), 0)) {
        TEST_error("big message could not be assigned");
        goto end;
    }
    if (!TEST_int_gt(send_message(clientssl, serverssl,
                                  &message_chunks, &curr_num_messages,
                                  big_message, big_message_len, read_buffer),
                     0)) {
        TEST_error("Error sending message: %*s", (int)big_message_len,
                   big_message);
        goto end;
    }

    if (!TEST_int_gt(exchange_evidence(serverssl, clientssl, read_buffer), 0))
        goto end;

    if (!TEST_ptr
        (sens_mtrx =
         extend_sens_mtrx(sens_mtrx, prev_num_messages, message_chunks,
                          curr_num_messages))) {
        TEST_perror("Error creating sensitive matrix");
        goto end;
    }
    prev_num_messages = curr_num_messages;

    if (!TEST_int_gt
        (SSL_tlsn_hide_sensitive_chunks
         (clientssl, INCLUDE_CERT_CHAIN, sens_mtrx, curr_num_messages), 0)) {
        TEST_perror("Error hiding chunks");
        goto end;
    }

    if (!TEST_int_gt
        (SSL_tls_get_proof_string(clientssl, &proof_str, &proof_len), 0)) {
        TEST_perror("Error parsing proof");
        goto end;
    }

    now = get_micro_time();     //in microseconds
    if (!TEST_int_gt
        (SSL_tlsn_verify_with_certchain
         (clientssl, proof_str, proof_len, now - MAX_DURATION, now,
          now - MAX_DURATION, now, MAX_DURATION), 0)) {
        TEST_perror("Error reading evidence");
        goto end;
    } else {
        TEST_info("Third evidence verified successfully\n");
    }

    testresult = 1;
 end:
    if (testresult == 0)
        TEST_info("%s \n", ERR_error_string(ERR_get_error(), NULL));
    free_sens_mtrx(sens_mtrx, curr_num_messages);
    OPENSSL_free(message_chunks);
    OPENSSL_free(read_buffer);
    OPENSSL_free(message);
    shutdown_ssl_connection(serverssl, clientssl);
    SSL_CTX_free(serverctx);
    SSL_CTX_free(clientctx);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(tlsn_robustness);
    return 1;
}
