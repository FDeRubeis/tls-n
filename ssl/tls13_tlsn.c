#include "ssl_locl.h"
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <netinet/in.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <sys/time.h>
#include <openssl/stack.h>
#include <openssl/safestack.h>
#include <regex.h>

#define TLS13_MAX_LABEL_LEN 246
#define StdCTX SSL_EXT_TLS1_3_ONLY|SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_SERVER_HELLO|SSL_EXT_IGNORE_ON_RESUMPTION
#define TLSN_EXT_TYPE 2
#define TLSN_TIMEOUT 100        //Number of seconds for the select timeout

//char *SALT_TREE_LABEL = "TLSNSaltTree";
unsigned char SALT_TREE_LABEL[] =
    { 0x00, 0x14, 0x12, 't', 'l', 's', '1', '3', ' ', 'T', 'L', 'S', 'N', 'S',
'a', 'l', 't', 'T', 'r', 'e', 'e', 0x00 };
size_t SALTTREE_LABEL_LEN = sizeof(SALT_TREE_LABEL);
unsigned char SALT_SECR_LABEL[] =
    { 0x00, 0x13, 0x11, 't', 'l', 's', '1', '3', ' ', 's', 'a', 'l', 't', ' ',
's', 'e', 'c', 'r', 'e', 't', 0x00 };
size_t SALTSECR_LABEL_LEN = sizeof(SALT_SECR_LABEL);

unsigned char merkle_root_marker = 0;
unsigned char hash_chain_marker = 1;

#define PROOF_BUFFER_SIZE (sizeof(unsigned char *) + sizeof(uint64_t) + sizeof(uint64_t))
typedef struct proof_buffer_str {
    unsigned char *buf;
    uint64_t buf_len;
    uint64_t offset;
} PROOF_BUFFER;

/* NOTE: in this structure the values are saved in network byte order */
#define HIDDEN_PLAINTEXT_PROOF_NODE_SIZE (sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t))
typedef struct hidden_plaintext_proof_node_str {
    uint16_t len_record;        /*Note: this refers to the length of the record including the hidden chunks */
    uint16_t num_salts;
    uint16_t num_hashes;
    uint8_t gen_orig;           /* the record sent by the generator? */
} HIDDEN_PLAINTEXT_PROOF_NODE;

/* Proof paramaters. NOTE: in this structure the values are saved in network byte order */
#define PLAINTEXT_PROOF_NODE_SIZE (sizeof(uint16_t) + sizeof(uint8_t))
typedef struct plaintext_proof_node_str {
    uint16_t len_record;
    uint8_t gen_orig;           /* the record sent by the generator */
} PLAINTEXT_PROOF_NODE;

/* It defines the different proof node types:
 * hash_chain_node: describes a record about which only Hash Chain element is provided
 * plaintext_node: describes a record about which the plaintext and salt secret are provided
 * merkle_hash_node: describes a record about which the Merkle Hash is provided
 * hidden_plaintext_node: describes a record about which SOME parts of the plaintext are hidden
 */
typedef enum {
    hash_chain_node = 1,
    plaintext_node = 2,
    merkle_hash_node = 3,
    hidden_plaintext_node = 4
} TLSN_NODE_TYPE;

#define PROOF_NODE_SIZE 1
typedef struct proof_node_str {
    TLSN_NODE_TYPE node_type;
} PROOF_NODE;

/* Proof paramaters. NOTE: in this structure, the values are saved in network byte order */
#define PROOF_PAR_SIZE (sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint64_t)  + sizeof(uint32_t) + sizeof(uint16_t) )
typedef struct proof_par_str {
    uint8_t tlsn_version;
    uint8_t hash_type;
    uint16_t salt_size;
    uint16_t chunk_size;
    uint16_t sig_len;           // Signature is placed directly after this struct
    uint64_t start_time;
    uint64_t stop_time;
    uint32_t num_proof_nodes;
    uint16_t cert_chain_len;    // Certificate Chain is placed after the signature
} PROOF_PAR;

/*NOTE: in this structure, the values are saved in network byte order */
#define RESPONSE_DATA_SIZE (sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t))
typedef struct response_data_str {
    uint64_t timestamp_start;
    uint64_t timestamp_stop;
    uint32_t ordering_vector_len;
    uint16_t sig_len;
} RESPONSE_DATA;

/* location of a salt in the salt tree. Note: in this structure, data are saved in network bte order */
#define PROOF_SALT_LOC_SIZE (sizeof(uint16_t) + sizeof(uint16_t))
typedef struct proof_salt_loc_str {
    uint16_t tree_level;
    uint16_t salt_index;
} PROOF_SALT_LOC;

/*Note: in this struct, data are saved in network bte order */
#define PROOF_MERKLE_LOC_SIZE (sizeof(uint16_t) + sizeof(uint16_t))
typedef struct proof_hashes_node_str {
    uint16_t tree_level;
    uint16_t chunk_index;
} PROOF_HASH_LOC;

// Record parameters
typedef struct record_proof_info_str {
    const size_t salt_size;
    const size_t chunk_size;
    const EVP_MD *hash_type;    /*hash used for the PRF generator */
    const size_t hash_size;
    const unsigned char *buf;   /*plaintext of record */
    size_t buf_length;
    const uint16_t num_chunks;  /*number of chunks in which the data will be split */
    const uint16_t tree_levels; /*number of levels of the merkle and salt trees */
    unsigned char **salts;      /*array of pointers to the generated salts. During the proof 
                                 *computation, it is overwritten with the salts to be sent in the proof*/
    uint16_t salt_index;        /*index used for iteration for computation of the salt tree */
    uint16_t chunk_index;       /*index used for iteration for computation of the Merkle  tree */
    EVP_MD_CTX *mdctx;
    unsigned char gen_orig;     /*it is 1 if the message was sent by the server */

    /*The following fields are used only for proof generation */
    uint16_t *hidden_chunks_ids;
    uint16_t num_hidden_chunks;
    PROOF_HASH_LOC *hash_locs;  /*locations of the hidden nodes in the tree. The storage is in network byte order */
    unsigned char **proof_merkle_hashes; /*hashes of the hidden nodes */
    uint16_t num_hashes;        /*number of the hashes of the hidden nodes */
    PROOF_SALT_LOC *salt_locs;  /* the location of the salts to be sent in the proof. The storage is in network byte order */
    /*the salts to be sent in the proof are stored in unsigned char **salts */
    uint16_t num_salts;         /*number of salts to be sent in the proof */

    uint8_t init_from_proof;    /*It is 1 if the record was initialized
                                 *extracting information from a proof */
} RECORD_PROOF_INFO;

static int SSL_set_tlsn_version(SSL *s, uint8_t value)
{
    if (s == NULL) {
        return 0;
    } else if (value > MAXIMUM_TLSN_VERSION) {
        SSLerr(SSL_F_SSL_SET_TLSN_VERSION, SSL_R_BAD_VALUE);
        return 0;
    } else {
        s->ext.tlsn_version = value;
        return 1;
    }
}

static int SSL_set_negotiated(SSL *s, int value)
{
    if (s == NULL) {
        return 0;
    } else if (value < 0 || value > 1) {
        SSLerr(SSL_F_SSL_SET_NEGOTIATED, SSL_R_BAD_VALUE);
        return 0;
    } else {
        s->ext.negotiated = value;
        return 1;
    }
}

int SSL_get_negotiated(SSL *s)
{
    return s->ext.negotiated;
}

int SSL_CTX_set_chunk_size(SSL_CTX *ctx, size_t value)
{
    if (ctx == NULL) {
        SSLerr(SSL_F_SSL_CTX_SET_CHUNK_SIZE, SSL_R_NULL_SSL_CTX);
        return 0;
    } else if (value == 0) {
        ctx->ext.chunk_size = MAXIMUM_CHUNK_SIZE;
        return 1;
    } else if (value < MINIMUM_CHUNK_SIZE || value > MAXIMUM_CHUNK_SIZE) {
        SSLerr(SSL_F_SSL_CTX_SET_CHUNK_SIZE, SSL_R_BAD_VALUE);
        return 0;
    } else {
        ctx->ext.chunk_size = value;
        return 1;
    }
}

size_t SSL_CTX_get_chunk_size(SSL_CTX *ctx)
{
    return ctx->ext.chunk_size;
}

int SSL_set_chunk_size(SSL *s, size_t value)
{
    if (s == NULL) {
        return 0;
    } else if (value == 0) {
        s->ext.chunk_size = MAXIMUM_CHUNK_SIZE;
        return 1;
    } else if (value < MINIMUM_CHUNK_SIZE || value > MAXIMUM_CHUNK_SIZE) {
        SSLerr(SSL_F_SSL_SET_CHUNK_SIZE, SSL_R_BAD_VALUE);
        return 0;
    } else {
        s->ext.chunk_size = value;
        return 1;
    }
}

size_t SSL_get_chunk_size(SSL *s)
{
    return s->ext.chunk_size;
}

int SSL_CTX_set_salt_size(SSL_CTX *ctx, size_t value)
{
    if (ctx == NULL) {
        SSLerr(SSL_F_SSL_CTX_SET_SALT_SIZE, SSL_R_NULL_SSL_CTX);
        return 0;
    } else if (value < MINIMUM_SALT_SIZE || value > MAXIMUM_SALT_SIZE) {
        SSLerr(SSL_F_SSL_CTX_SET_SALT_SIZE, SSL_R_BAD_VALUE);
        return 0;
    } else {
        ctx->ext.salt_size = value;
        return 1;
    }
}

size_t SSL_CTX_get_salt_size(SSL_CTX *ctx)
{
    return ctx->ext.salt_size;
}

int SSL_set_salt_size(SSL *s, size_t value)
{
    if (s == NULL) {
        return 0;
    } else if (value < MINIMUM_SALT_SIZE || value > MAXIMUM_SALT_SIZE) {
        SSLerr(SSL_F_SSL_SET_SALT_SIZE, SSL_R_BAD_VALUE);
        return 0;
    } else {
        s->ext.salt_size = value;
        return 1;
    }
}

size_t SSL_get_salt_size(SSL *s)
{
    return s->ext.salt_size;
}

uint8_t SSL_CTX_get_tlsn_version(SSL_CTX *ctx)
{
    return ctx->ext.tlsn_version;
}

uint8_t SSL_get_tlsn_version(SSL *s)
{
    return s->ext.tlsn_version;
}

int SSL_get_tlsn_sent_responses(SSL *s)
{
    return s->ext.tlsn_sent_responses;
}

int SSL_get_tlsn_received_responses(SSL *s)
{
    return s->ext.tlsn_received_responses;
}

/* Struct for parameter negotiation */
#define TLSN_NEGOTIATION_PARAMETERS_SIZE sizeof(size_t)*2 + sizeof(uint8_t)
typedef struct tlsn_negotiation_parameters_str {
    size_t chunk_size;
    size_t salt_size;
    uint8_t tlsn_version;
} TLSN_NEGOTIATION_PARAMETERS;

//Add Callback function of the client
static int send_extension_data(SSL *s, unsigned int ext_type,
                               unsigned int context,
                               const unsigned char **out,
                               size_t *outlen, X509 *x,
                               size_t chainidx, int *al, void *add_arg)
{
    *outlen = TLSN_NEGOTIATION_PARAMETERS_SIZE;
    TLSN_NEGOTIATION_PARAMETERS *params =
        (TLSN_NEGOTIATION_PARAMETERS *) malloc(*outlen);
    params->chunk_size = SSL_get_chunk_size(s);
    params->salt_size = SSL_get_salt_size(s);
    params->tlsn_version = SSL_get_tlsn_version(s);

    SSL_set_negotiated(s, 1);
    *out = (unsigned char *)params;

    return 1;
}

//Free callback to free the dynamic memory allocation of send_extension_data
static void free_extension_data(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char *out, void *add_arg)
{
    free((void *)out);
}

static int parsing_extension_data(SSL *s, unsigned int ext_type,
                                  unsigned int context,
                                  const unsigned char *in,
                                  size_t inlen, X509 *x,
                                  size_t chainidx, int *al, void *parse_arg)
{
    TLSN_NEGOTIATION_PARAMETERS *params = (TLSN_NEGOTIATION_PARAMETERS *) in;
    if (inlen != TLSN_NEGOTIATION_PARAMETERS_SIZE
        || (SSL_set_chunk_size(s, params->chunk_size) < 1)
        || (SSL_set_salt_size(s, params->salt_size) < 1)
        || SSL_set_tlsn_version(s, params->tlsn_version) < 1) {
        SSLerr(SSL_F_PARSING_EXTENSION_DATA,
               SSL_R_INCORRECT_NEGOTIATION_PARAMETERS);
        SSL_set_negotiated(s, 0);
        return 0;
    } else {
        SSL_set_negotiated(s, 1);
        return 1;
    }
}

int SSL_CTX_set_tlsn_extension_client(SSL_CTX *ctx)
{
    return SSL_CTX_add_custom_ext(ctx, TLSN_EXT_TYPE, StdCTX,
                                  send_extension_data, free_extension_data,
                                  NULL, NULL, NULL);
}

int SSL_CTX_set_tlsn_extension_server(SSL_CTX *ctx)
{
    return SSL_CTX_add_custom_ext(ctx, TLSN_EXT_TYPE, StdCTX, NULL, NULL, NULL,
                                  parsing_extension_data, NULL);
}

/*Makes sure reading and writing routines work with non-blocking sockets*/
static int check_availability(SSL *ssl, int err)
{

    int fd = SSL_get_fd(ssl);
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(fd, &fdset);

    switch (SSL_get_error(ssl, err)) {
    case SSL_ERROR_NONE:
        return 1;
        break;
    case SSL_ERROR_WANT_READ:
        return select(fd + 1, (void *)&fdset, NULL, NULL, NULL);
        break;
    case SSL_ERROR_WANT_WRITE:
        return select(fd + 1, NULL, (void *)&fdset, NULL, NULL);
        break;
    default:
        return -1;
    }
}

static uint64_t get_micro_time()
{
    struct timeval currentTime;
    gettimeofday(&currentTime, NULL);
    return (uint64_t)currentTime.tv_sec * (uint64_t)1e6 + currentTime.tv_usec;
}

static void free_rpi(RECORD_PROOF_INFO * rpi)
{
    if (rpi == NULL)
        return;

    if (rpi->salt_locs != NULL) {
        OPENSSL_free(rpi->salt_locs);
        rpi->salt_locs = NULL;
    }
    if (rpi->proof_merkle_hashes != NULL) {
        OPENSSL_free(rpi->proof_merkle_hashes[0]);
        OPENSSL_free(rpi->proof_merkle_hashes);
        rpi->proof_merkle_hashes = NULL;
    }
    if (rpi->hash_locs != NULL) {
        OPENSSL_free(rpi->hash_locs);
        rpi->hash_locs = NULL;
    }
    if (rpi->hidden_chunks_ids != NULL) {
        OPENSSL_free(rpi->hidden_chunks_ids);
        rpi->hidden_chunks_ids = NULL;
    }
    if (rpi->mdctx != NULL) {
        EVP_MD_CTX_destroy(rpi->mdctx);
        rpi->mdctx = NULL;
    }
    if (rpi->salts != NULL) {
        OPENSSL_free(rpi->salts[0]);
        OPENSSL_free(rpi->salts);
        rpi->salts = NULL;
    }

    OPENSSL_free(rpi);
    rpi = NULL;
}

/*Stores the important information about the record,
 * so it will be possible to build the proof later */
static int store_record_info(SSL *s, RECORD_PROOF_INFO * rpi, uint8_t received,
                             unsigned char *salt_secret, size_t ssecrlen)
{
    TLSN_CLIENT_RECORDING **recording_ptr =
        received ? &s->ext.tlsn_client_recv : &s->ext.tlsn_client_sent;
    size_t *len_ptr =
        received ? &s->ext.tlsn_client_recv_len : &s->ext.tlsn_client_sent_len;

    *recording_ptr =
        (TLSN_CLIENT_RECORDING *) OPENSSL_realloc(*recording_ptr,
                                                  (*len_ptr +
                                                   1) *
                                                  sizeof
                                                  (TLSN_CLIENT_RECORDING));
    if (recording_ptr == NULL)
        return 0;
    bzero(&((*recording_ptr)[*len_ptr]), sizeof(TLSN_CLIENT_RECORDING));

    (*recording_ptr)[*len_ptr].plaintext_size = rpi->buf_length;
    (*recording_ptr)[*len_ptr].plaintext =
        (unsigned char *)OPENSSL_malloc(rpi->buf_length);
    memcpy((*recording_ptr)[*len_ptr].plaintext, rpi->buf, rpi->buf_length);

    (*recording_ptr)[*len_ptr].salt_secret =
        (unsigned char *)OPENSSL_malloc(rpi->salt_size);
    memcpy((*recording_ptr)[*len_ptr].salt_secret, salt_secret, ssecrlen);
    (*recording_ptr)[*len_ptr].merkle_hash = NULL;

    (*len_ptr)++;

    return 1;
}

static int update_ordering_vector(SSL *s, uint8_t received)
{
    if (s->ext.tlsn_ordvec_len % 8 == 0) {

        s->ext.tlsn_ordvec =
            OPENSSL_realloc(s->ext.tlsn_ordvec, s->ext.tlsn_ordvec_len / 8 + 1);
        if (s->ext.tlsn_ordvec == NULL)
            return 0;

        s->ext.tlsn_ordvec[s->ext.tlsn_ordvec_len / 8] = 0;
    }

    /*if the message was sent by the server */
    if (received != s->server) {
        s->ext.tlsn_ordvec[s->ext.tlsn_ordvec_len / 8] |=
            1 << (s->ext.tlsn_ordvec_len % 8);
    }

    s->ext.tlsn_ordvec_len++;

    /* If we have reached the MAX_ORD_VECTOR_LEN, we have to send an ordering vector message */
    if ((s->ext.tlsn_ordvec_len % MAX_ORD_VECTOR_LEN) == 0 && s->server) {

        /* The ord vec message is sent here if we are in reading routine. 
         * It is sent later if we are in writing routine */
        if (received) {
            if (tlsn_send_ord_vector(s) <= 0)
                return -1;
        }
        /* If we are in writing routine, the increase of this counter
         * will trigger the sending of the ordering vector later.
         */
        s->ext.tlsn_exchanged_ordvec++;
    }

    return 1;
}

/*It adds the computed merkle root of the record to the TLS-N session's hash chain*/
static unsigned char *advance_hash_chain(RECORD_PROOF_INFO * rpi,
                                         unsigned char *hash_chain,
                                         unsigned char *hash)
{

    unsigned int hashsize = (unsigned int)rpi->hash_size;

    if (1 != EVP_DigestInit_ex(rpi->mdctx, rpi->hash_type, NULL)
        || 1 != EVP_DigestUpdate(rpi->mdctx, &hash_chain_marker,
                                 sizeof(hash_chain_marker)))
        return NULL;

    if (hash_chain != NULL) {
        if (1 != EVP_DigestUpdate(rpi->mdctx, hash_chain, rpi->hash_size))
            return NULL;
    } else {
        hash_chain = OPENSSL_malloc(rpi->hash_size);
    }

    if (1 != EVP_DigestUpdate(rpi->mdctx, hash, rpi->hash_size)
        || 1 != EVP_DigestFinal_ex(rpi->mdctx, hash_chain, &hashsize))
        return NULL;

    return hash_chain;
}

static int get_chunk_length2(RECORD_PROOF_INFO * rpi, int chunk_index)
{
    if (chunk_index + 1 < rpi->num_chunks) {
        return rpi->chunk_size;
    } else {
        return rpi->buf_length - rpi->chunk_size * chunk_index;
    }
}

static int get_chunk_length(RECORD_PROOF_INFO * rpi)
{
    return get_chunk_length2(rpi, rpi->chunk_index);
}

static int num_skipped_leaves(RECORD_PROOF_INFO * rpi, uint16_t level,
                              uint16_t chunk_index)
{
    if (level == rpi->tree_levels) {
        return 1;
    }
    if (level == 0) {
        return rpi->num_chunks;
    }
    // Compute the maximal number of children
    uint16_t max_leaves = 1 << (rpi->tree_levels - level);
    if (max_leaves + chunk_index > rpi->num_chunks) {
        // All the remaining
        return rpi->num_chunks - chunk_index;
    } else {
        return max_leaves;
    }

}

static int is_hidden_chunk(uint16_t *hidden_chunks_ids,
                           uint16_t num_hidden_chunks, uint16_t chunk_id)
{
    int i;
    for (i = 0; i < num_hidden_chunks; ++i) {
        if (hidden_chunks_ids[i] == chunk_id) {
            return 1;
        }
    }
    return 0;
}

static int32_t hash_is_in_proof(PROOF_HASH_LOC * hash_locs, uint16_t num_hashes,
                                int level, uint16_t chunk_index)
{
    uint16_t i;
    for (i = 0; i < num_hashes; ++i) {
        if (be16toh(hash_locs[i].tree_level) == level
            && be16toh(hash_locs[i].chunk_index) == chunk_index) {
            return i;
        }
    }
    return -1;
}

/* outbuf has to be of length hash_size */
static int compute_merkle_tree2(RECORD_PROOF_INFO * rpi, int level,
                                unsigned char *outbuf)
{
    unsigned char *left_child = OPENSSL_malloc(rpi->hash_size);
    unsigned char *right_child = OPENSSL_malloc(rpi->hash_size);
    size_t chunk_length;
    unsigned int out_len;

    if (rpi->chunk_index >= rpi->num_chunks) {
        goto ret;
    }

    /* Use existing hashes when computing merkle tree from proof
     * The following clause can only be true if we are in proof verification */
    if (rpi->num_hashes != 0) {
        int32_t in_proof_index =
            hash_is_in_proof(rpi->hash_locs, rpi->num_hashes, level,
                             rpi->chunk_index);
        if (in_proof_index != -1) {
            memcpy(outbuf, rpi->proof_merkle_hashes[in_proof_index],
                   rpi->hash_size);
            if (!is_hidden_chunk
                (rpi->hidden_chunks_ids, rpi->num_hidden_chunks,
                 rpi->chunk_index))
                goto err;
            rpi->chunk_index +=
                num_skipped_leaves(rpi, level, rpi->chunk_index);
            goto ret;
        }
    }

    chunk_length = get_chunk_length(rpi);

    /* Check if this a leaf */
    if (level == rpi->tree_levels) {

        /* Compute hash from salt and chunk */
        if (1 != EVP_DigestInit_ex(rpi->mdctx, rpi->hash_type, NULL)
            || 1 != EVP_DigestUpdate(rpi->mdctx, rpi->salts[rpi->chunk_index],
                                     rpi->salt_size)
            || 1 != EVP_DigestUpdate(rpi->mdctx,
                                     &(rpi->
                                       buf[rpi->chunk_size * rpi->chunk_index]),
                                     chunk_length))
            goto err;

        /* Special case: Root node */
        if (level == 0) {
            uint16_t buf_length_nbo = htons((uint16_t)rpi->buf_length);
            if (1 !=
                EVP_DigestUpdate(rpi->mdctx,
                                 (unsigned char *)&merkle_root_marker,
                                 sizeof(merkle_root_marker))
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         (unsigned char *)&buf_length_nbo,
                                         sizeof(buf_length_nbo))
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         (unsigned char *)&(rpi->gen_orig),
                                         sizeof(rpi->gen_orig)))
                goto err;
        }

        if (1 != EVP_DigestFinal_ex(rpi->mdctx, outbuf, &out_len))
            goto err;

        rpi->chunk_index += 1;
        goto ret;

    } else {
        if (compute_merkle_tree2(rpi, level + 1, left_child) <= 0)
            goto err;

        /* If we don't need the right side any more, just push the left side upwards */
        if (rpi->chunk_index >= rpi->num_chunks) {
            memcpy(outbuf, left_child, rpi->hash_size);
            goto ret;
        }

        if (compute_merkle_tree2(rpi, level + 1, right_child) <= 0)
            goto err;
        if (1 != EVP_DigestInit_ex(rpi->mdctx, rpi->hash_type, NULL)
            || 1 != EVP_DigestUpdate(rpi->mdctx, left_child, rpi->hash_size)
            || 1 != EVP_DigestUpdate(rpi->mdctx, right_child, rpi->hash_size))
            goto err;

        /* Special case: Root node */
        if (level == 0) {
            uint16_t buf_length_nbo = htons((uint16_t)rpi->buf_length);
            if (1 !=
                EVP_DigestUpdate(rpi->mdctx, &merkle_root_marker,
                                 sizeof(merkle_root_marker))
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         (unsigned char *)&(buf_length_nbo),
                                         sizeof(buf_length_nbo))
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         (unsigned char *)&(rpi->gen_orig),
                                         sizeof(rpi->gen_orig)))
                goto err;
        }

        if (1 != EVP_DigestFinal_ex(rpi->mdctx, outbuf, &out_len))
            goto err;

 ret:
        OPENSSL_free(left_child);
        OPENSSL_free(right_child);
        return 1;

 err:
        OPENSSL_free(left_child);
        OPENSSL_free(right_child);
        return 0;
    }
}

/* outbuf has to be of length hash_size */
static int compute_merkle_tree(RECORD_PROOF_INFO * rpi, unsigned char *outbuf)
{
    rpi->chunk_index = 0;
    rpi->num_hashes = 0;
    return compute_merkle_tree2(rpi, 0, outbuf);
}

static int compute_hkdf_expansion(const EVP_MD *md,
                                  const unsigned char *secret,
                                  size_t secret_len, const unsigned char *label,
                                  size_t labellen, const unsigned char *data,
                                  size_t datalen, unsigned char *out,
                                  size_t outlen)
{

    unsigned int hash_size = (size_t)EVP_MD_meth_get_result_size(md);
    uint8_t iterations = outlen / hash_size + 1;
    uint8_t i;
    size_t curr_bytes_toget;
    unsigned char hmac_out[hash_size];
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL)
        goto err;

    for (i = 1; i <= iterations; i++) {

        curr_bytes_toget =
            (i == iterations) ? (outlen - ((i - 1) * hash_size)) : hash_size;

        if ((!HMAC_Init_ex(ctx, secret, (int)secret_len, md, NULL)))
            goto err;

        if (i != 1) {
            if (!HMAC_Update(ctx, hmac_out, hash_size))
                goto err;
        }

        if (1 != HMAC_Update(ctx, label, labellen)
            || 1 != HMAC_Update(ctx, &i, 1)
            || 1 != HMAC_Final(ctx, hmac_out, &hash_size))
            goto err;

        memcpy(out + (hash_size * (i - 1)), hmac_out, curr_bytes_toget);
    }

    HMAC_CTX_free(ctx);
    return 1;

 err:
    HMAC_CTX_free(ctx);
    return -1;

}

static int compute_salt_tree2(RECORD_PROOF_INFO * rpi, const int level,
                              unsigned char *salt_secret)
{

    unsigned char *new_salt = OPENSSL_malloc(2 * rpi->salt_size);
    size_t new_salt_len = 2 * rpi->salt_size;
    unsigned char *left;
    unsigned char *right;

    if (rpi->salt_index >= rpi->num_chunks) {
        goto ret;
    }

    if (rpi->num_chunks == 1) {
        memcpy(rpi->salts[rpi->salt_index], salt_secret, rpi->salt_size);
        rpi->salt_index += 1;
        goto ret;
    }

    if (compute_hkdf_expansion
        (rpi->hash_type, salt_secret, rpi->salt_size, SALT_TREE_LABEL,
         SALTTREE_LABEL_LEN, NULL, 0, new_salt, new_salt_len) < 1)
        goto err;
    left = new_salt;
    right = new_salt + rpi->salt_size;

    /* Left side */

    /* Check if  leaf */
    if (level == rpi->tree_levels - 1) {
        /* Save salt values if  bottom is reached */
        memcpy(rpi->salts[rpi->salt_index], left, rpi->salt_size);
        rpi->salt_index += 1;
    } else {
        /* Go to lower level */
        if (compute_salt_tree2(rpi, level + 1, left) <= 0)
            goto err;
    }

    if (rpi->salt_index >= rpi->num_chunks)
        goto ret;

    /* Right side */

    /* Check if  leaf */
    if (level == rpi->tree_levels - 1) {
        if (rpi->salt_index >= rpi->num_chunks)
            goto err;

        memcpy(rpi->salts[rpi->salt_index], right, rpi->salt_size);
        rpi->salt_index += 1;
    } else {
        /*Go to lower level */
        if (compute_salt_tree2(rpi, level + 1, right) <= 0)
            goto err;
    }

 ret:
    OPENSSL_free(new_salt);
    return 1;

 err:
    OPENSSL_free(new_salt);
    return 0;
}

static int compute_salt_tree(RECORD_PROOF_INFO * rpi,
                             unsigned char *salt_secret)
{
    rpi->salt_index = 0;
    int rv = compute_salt_tree2(rpi, 0, salt_secret);
    if (rpi->num_chunks != rpi->salt_index)
        return 0;

    return rv;
}

static unsigned char *encode_nbo(uint64_t value, unsigned int bytes,
                                 unsigned char *ptr)
{
    uint64_t converted;

    converted = htobe64(value);
    memcpy(ptr, ((unsigned char *)(&converted)) + (sizeof(converted) - bytes),
           bytes);
    return ptr + bytes;
}

/* Computes the salt secret of the record and stores it in salt_secret*/
static int extract_salt_secret(SSL *s, uint8_t received,
                               RECORD_PROOF_INFO * rpi,
                               unsigned char *salt_secret,
                               size_t *salt_secr_len)
{
    unsigned char *key;

    if (s->server == 1) {
        key =
            received ? s->client_app_traffic_secret : s->
            server_app_traffic_secret;
    } else {
        key =
            received ? s->server_app_traffic_secret : s->
            client_app_traffic_secret;
    }

    if (key == NULL)
        return 0;

    size_t key_length = rpi->hash_size;

    /* Take the read/write sequence from the record. For the first message, it gives 0002, for the second 0003 and so on... */
    unsigned char *nonce;
    nonce = received ? s->rlayer.read_sequence : s->rlayer.write_sequence;
    size_t nonce_length = SEQ_NUM_SIZE;

    if (nonce == NULL)
        return 0;

    unsigned char tmp_secret[key_length + nonce_length];
    memcpy(tmp_secret, nonce, nonce_length);
    memcpy(tmp_secret + nonce_length, key, key_length);

    if (compute_hkdf_expansion
        (rpi->hash_type, tmp_secret, key_length + nonce_length, SALT_SECR_LABEL,
         SALTSECR_LABEL_LEN, NULL, 0, salt_secret, *salt_secr_len) < 1)
        return 0;

    return 1;
}

/*Initializes the pointes to the salts that will be generated in the tree. They are saved in the RecordProofInof structure*/
static unsigned char **allocate_string_array(size_t string_size,
                                             size_t num_strings)
{
    unsigned int i;

    /*allocate the vector of salts-pointers */
    unsigned char **string_array =
        (unsigned char **)OPENSSL_malloc(sizeof(unsigned char *) * num_strings);
    if (string_array == NULL)
        return NULL;

    /* Allocate salts */
    string_array[0] =
        (unsigned char *)OPENSSL_malloc(string_size * num_strings);
    if (string_array[0] == NULL)
        return NULL;

    /*give the pointers the adresses of the salts */
    for (i = 1; i < num_strings; ++i) {
        string_array[i] = string_array[i - 1] + string_size;
    }
    return string_array;
}

/*it computes the logarthm base 2 and rounds it up*/
static uint64_t logb2(uint64_t arg)
{
    uint64_t tmp = arg;
    int i, k;
    uint64_t or = 0;

    for (i = 0; tmp != 0; i++) {
        tmp >>= 1;
    }
    for (k = 0; k < i - 1; k++) {
        or = or || (arg & (1 << k));
    }

    return (i - 1) + or;
}

static uint64_t roundup(uint64_t dividend, uint64_t divisor)
{
    uint64_t tmp = (double)dividend / divisor;
    tmp += ((dividend % divisor) != 0);
    return tmp;
}

/* Initializes the RecordProofInfo structure containing all the necessary information about the record for constructing the evidence and the proof*/
static RECORD_PROOF_INFO *init_rpi(SSL *s, const unsigned char *buf,
                                   size_t buf_length, uint8_t received)
{
    RECORD_PROOF_INFO rpival = {
        .salt_size = SSL_get_salt_size(s),
        .chunk_size = SSL_get_chunk_size(s),
        .hash_type = ssl_handshake_md(s),
        .hash_size = (size_t)EVP_MD_meth_get_result_size(rpival.hash_type),
        .num_chunks = roundup((uint64_t)buf_length, rpival.chunk_size),
        .tree_levels = logb2(rpival.num_chunks),
        .gen_orig = received ^ s->server
    };

    rpival.buf = buf;
    rpival.buf_length = buf_length;
    rpival.salts = NULL;
    rpival.salt_index = 0;
    rpival.chunk_index = 0;
    rpival.mdctx = EVP_MD_CTX_create();
    rpival.hidden_chunks_ids = NULL;
    rpival.num_hidden_chunks = 0;
    rpival.num_hashes = 0;
    rpival.hash_locs = NULL;
    rpival.proof_merkle_hashes = NULL;
    rpival.salt_locs = NULL;
    rpival.init_from_proof = 0;

    RECORD_PROOF_INFO *rpi;
    if ((rpi =
         (RECORD_PROOF_INFO *) OPENSSL_malloc(sizeof(RECORD_PROOF_INFO))) ==
        NULL)
        return NULL;
    memcpy(rpi, &rpival, sizeof(rpival));
    rpi->salts = allocate_string_array(rpi->salt_size, rpi->num_chunks);
    if (rpi->salts == NULL)
        return NULL;

    return rpi;
}

int SSL_add_record_to_evidence(SSL *s, const unsigned char *buf,
                               size_t buf_length, uint8_t received)
{

    if (SSL_get_negotiated(s) != 1)
        return 0;

    if (SSL_get_salt_size(s) < MINIMUM_SALT_SIZE
        || SSL_get_salt_size(s) > MAXIMUM_SALT_SIZE
        || SSL_get_chunk_size(s) < MINIMUM_CHUNK_SIZE
        || SSL_get_chunk_size(s) > MAXIMUM_CHUNK_SIZE)
        return 0;

    if (SSL_get_tlsn_version(s) != 0)
        return 0;

    /*Temporary workaround for tlsn extension: ssl_write, in non blocking
     * mode, can execute the current routine twice for the same record.
     * We don't want that for the tlsn extension, so we use s->ext.tlsn_last_seq_num
     */
    memcpy(s->ext.tlsn_last_seq_num, s->rlayer.write_sequence, SEQ_NUM_SIZE);

    if (s->ext.tlsn_timestamp_start == 0) {
        s->ext.tlsn_timestamp_start = get_micro_time();
    }

    RECORD_PROOF_INFO *rpi = init_rpi(s, buf, buf_length, received);
    if (rpi == NULL)
        return 0;

    unsigned char merkle_hash[rpi->hash_size];
    unsigned char salt_secret[rpi->salt_size];
    size_t salt_secr_len = sizeof(salt_secret);

    if (extract_salt_secret(s, received, rpi, salt_secret, &salt_secr_len) <= 0)
        goto err;

    if (s->server) {

        if (compute_salt_tree(rpi, salt_secret) <= 0)
            goto err;

        if (compute_merkle_tree(rpi, merkle_hash) <= 0)
            goto err;

        s->ext.tlsn_final_hash =
            advance_hash_chain(rpi, s->ext.tlsn_final_hash, merkle_hash);
        if (s->ext.tlsn_final_hash == NULL)
            goto err;

        if (update_ordering_vector(s, received) <= 0)
            goto err;

    } else {

        if (update_ordering_vector(s, received) <= 0)
            goto err;

        /*Stores the important information about the record */
        if (store_record_info(s, rpi, received, salt_secret, salt_secr_len) <=
            0)
            goto err;
    }

    free_rpi(rpi);
    return 1;

 err:
    free_rpi(rpi);
    return 0;
}

/* It is called by the server when the size of the ordering vector reaches 
 * MAX_ORD_VEC. It sends the ordering vector to the client.
 */
int tlsn_send_ord_vector(SSL *s)
{

    size_t ord_vector_msg_len =
        (s->ext.tlsn_ordvec_len - 1) / 8 + 1 + TLSN_MESSAGE_TYPE_SIZE;
    unsigned char *ord_vector_msg = OPENSSL_malloc(ord_vector_msg_len);
    if (ord_vector_msg == NULL)
        return 0;
    *ord_vector_msg = tlsn_message_type_ordering_vector;
    memcpy(ord_vector_msg + TLSN_MESSAGE_TYPE_SIZE, s->ext.tlsn_ordvec,
           (s->ext.tlsn_ordvec_len - 1) / 8 + 1);

    size_t tlsn_written;
    int r;
    while ((r =
            s->method->ssl_write_bytes(s, SSL3_RT_TLSN_MESSAGE, ord_vector_msg,
                                       ord_vector_msg_len,
                                       &tlsn_written)) < 0) {
        if (check_availability(s, r) < 0) {
            OPENSSL_free(ord_vector_msg);
            ord_vector_msg = NULL;
            return 0;
        }
    }

    OPENSSL_free(ord_vector_msg);
    ord_vector_msg = NULL;
    s->ext.tlsn_ordvec_len = 0;
    OPENSSL_free(s->ext.tlsn_ordvec);
    s->ext.tlsn_ordvec = NULL;
    return 1;
}

static int SSL_set_option(SSL *s, int option)
{
    if (s == NULL) {
        return 0;
    } else if (option > OMIT_CERT_CHAIN) {
        return 0;
    } else {
        s->ext.request_option = option;
        return 1;
    }
}

/* The possible options are OMIT_CERT_CHAIN and INCLUDE_CERT_CHAIN */
int SSL_tlsn_request_evidence(SSL *s, int option)
{

    if (SSL_get_negotiated(s) != 1) {
        SSLerr(SSL_F_SSL_TLSN_REQUEST_EVIDENCE, SSL_R_EXTENSION_NOT_NEGOTIATED);
        return -1;
    }

    if (SSL_get_salt_size(s) < MINIMUM_SALT_SIZE
        || SSL_get_salt_size(s) > MAXIMUM_SALT_SIZE
        || SSL_get_chunk_size(s) < MINIMUM_CHUNK_SIZE
        || SSL_get_chunk_size(s) > MAXIMUM_CHUNK_SIZE) {
        SSLerr(SSL_F_SSL_TLSN_REQUEST_EVIDENCE,
               SSL_R_SALT_OR_CHUNK_SIZE_NOT_CORRECTLY_NEGOTIATED);
        return -1;
    }

    if (SSL_set_option(s, option) < 1) {
        SSLerr(SSL_F_SSL_TLSN_REQUEST_EVIDENCE, SSL_R_INVALID_OPTION);
        return -1;
    }

    if (s->ext.tlsn_client_recv_len == 0 && s->ext.tlsn_client_sent_len == 0) {
        SSLerr(SSL_F_SSL_TLSN_REQUEST_EVIDENCE, SSL_R_NO_MESSAGE_EXCHANGED);
        return -1;
    }

    /*request evidence */
    unsigned char request = tlsn_message_type_request;
    size_t len = TLSN_MESSAGE_TYPE_SIZE;
    size_t written;
    int r;
    while ((r =
            s->method->ssl_write_bytes(s, SSL3_RT_TLSN_MESSAGE, &request, len,
                                       &written)) < 0) {
        if (check_availability(s, r) < 0)
            return 0;
    }

    return 1;
}

int SSL_tlsn_receive_response(SSL *s)
{

    int prev_rcvd_responses = SSL_get_tlsn_received_responses(s);
    int h = 0;
    char r[SSL3_RT_MAX_PLAIN_LENGTH + 1];
    while ((h = SSL_read(s, r, SSL3_RT_MAX_PLAIN_LENGTH)) < 0) {

        if (check_availability(s, h) < 0) {
            SSLerr(SSL_F_SSL_TLSN_RECEIVE_RESPONSE,
                   SSL_R_EVIDENCE_NOT_RECEIVED);
            return -1;
        }

    }
    if (h == 0 && SSL_get_tlsn_received_responses(s) == prev_rcvd_responses + 1) {
        return h;
    } else if (h > 0) {
        SSLerr(SSL_F_SSL_TLSN_RECEIVE_RESPONSE,
               SSL_R_RECEIVED_NON_TLSN_MESSAGE);
        return -1;
    } else {
        SSLerr(SSL_F_SSL_TLSN_RECEIVE_RESPONSE, SSL_R_EVIDENCE_NOT_RECEIVED);
        return -1;
    }
}

static const EVP_MD *from_hashalg_to_evpmd(uint8_t hashalg)
{
    switch (hashalg) {

    case TLSEXT_hash_sha224:
        return EVP_sha224();

    case TLSEXT_hash_sha256:
        return EVP_sha256();

    case TLSEXT_hash_sha384:
        return EVP_sha384();

    case TLSEXT_hash_sha512:
        return EVP_sha512();

    default:
        return NULL;
    }
}

static uint8_t from_evpmd_to_hashalg(const EVP_MD *hash_type)
{

    int nid = EVP_MD_type(hash_type);

    switch (nid) {

    case NID_sha224:
        return TLSEXT_hash_sha224;

    case NID_sha256:
        return TLSEXT_hash_sha256;

    case NID_sha384:
        return TLSEXT_hash_sha384;

    case NID_sha512:
        return TLSEXT_hash_sha512;

    default:
        return 0;
    }
}

static int EVP_DigestUpdate_nbo(EVP_MD_CTX *mdctx, uint64_t num,
                                size_t inbuf_len)
{

    uint16_t tmp2;
    uint32_t tmp4;
    uint64_t tmp8;
    if (inbuf_len == 2) {
        tmp2 = htobe16((uint16_t)num);
        return EVP_DigestUpdate(mdctx, (unsigned char *)&tmp2, inbuf_len);
    } else if (inbuf_len == 4) {
        tmp4 = htobe32((uint32_t)num);
        return EVP_DigestUpdate(mdctx, (unsigned char *)&tmp4, inbuf_len);
    } else if (inbuf_len == 8) {
        tmp8 = htobe64((uint64_t)num);
        return EVP_DigestUpdate(mdctx, (unsigned char *)&tmp8, inbuf_len);
    } else {
        return 0;
    }
}

/* Starting from the final hash and other session information, it generates the evidence */
static int generate_evidence_hash(SSL *s, const EVP_MD *hash_type,
                                  unsigned char *hashed_data,
                                  const size_t *hash_size_ptr,
                                  uint64_t tls_proof_timestamp_stop)
{
    uint8_t tlsn_version = 0;   /*version of the evidence */
    size_t chunk_size = s->ext.chunk_size;
    size_t salt_size = s->ext.salt_size;
    uint8_t hashalg = from_evpmd_to_hashalg(hash_type);
    unsigned int hash_size = *hash_size_ptr;
    if (hashalg == 0)
        return 0;

    if (s->ext.tlsn_final_hash == NULL) {
        SSLerr(SSL_F_GENERATE_EVIDENCE_HASH, SSL_R_NO_MESSAGE_EXCHANGED);
        return 0;
    }

    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_create()) == NULL
        || 1 != EVP_DigestInit_ex(mdctx, hash_type, NULL)
        || 1 != EVP_DigestUpdate(mdctx, &tlsn_version, 1)
        || 1 != EVP_DigestUpdate(mdctx, s->ext.tlsn_final_hash, *hash_size_ptr)
        || 1 != EVP_DigestUpdate_nbo(mdctx, s->ext.tlsn_timestamp_start, 8)
        || 1 != EVP_DigestUpdate_nbo(mdctx, tls_proof_timestamp_stop, 8)
        || 1 != EVP_DigestUpdate_nbo(mdctx, salt_size, 2)
        || 1 != EVP_DigestUpdate_nbo(mdctx, chunk_size, 2)
        || 1 != EVP_DigestUpdate(mdctx, (unsigned char *)&hashalg, 1)
        || 1 != EVP_DigestFinal_ex(mdctx, hashed_data, &hash_size)) {
        EVP_MD_CTX_destroy(mdctx);
        return 0;
    }

    EVP_MD_CTX_destroy(mdctx);
    return 1;
}

/*It generates the evidence and sends it to the requester */
static int tlsn_handle_message_request(SSL *s)
{
    const EVP_MD *hash_type = ssl_handshake_md(s);
    const size_t hash_size = (size_t)EVP_MD_meth_get_result_size(hash_type);
    uint64_t tls_proof_timestamp_stop = get_micro_time();
    EVP_PKEY *priv_key = SSL_get_privatekey(s);
    size_t signed_data_len;
    unsigned char *hashed_data = OPENSSL_malloc(hash_size);
    unsigned char *signed_data = NULL;
    EVP_PKEY_CTX *pkctx = NULL;
    unsigned char *response = NULL;

    if (hashed_data == NULL)
        return 0;

    if (generate_evidence_hash
        (s, hash_type, hashed_data, &hash_size, tls_proof_timestamp_stop) <= 0)
        goto err;

    /*signing the hash */
    if ((pkctx = EVP_PKEY_CTX_new(priv_key, NULL)) == NULL
        || EVP_PKEY_sign_init(pkctx) <= 0
        || EVP_PKEY_sign(pkctx, NULL, &signed_data_len, hashed_data,
                         hash_size) <= 0
        || (signed_data =
            (unsigned char *)OPENSSL_malloc(signed_data_len)) == NULL
        || EVP_PKEY_sign(pkctx, signed_data, &signed_data_len, hashed_data,
                         hash_size) <= 0) {
        goto err;
    }

    /*generate response message */
    size_t resp_len =
        TLSN_MESSAGE_TYPE_SIZE + RESPONSE_DATA_SIZE + signed_data_len +
        roundup(s->ext.tlsn_ordvec_len, 8);
    response = OPENSSL_malloc(resp_len);

    TLS_N_MESSAGE_TYPE message_type = tlsn_message_type_response;
    RESPONSE_DATA resp_data;
    resp_data.timestamp_start = htobe64(s->ext.tlsn_timestamp_start);
    resp_data.timestamp_stop = htobe64(tls_proof_timestamp_stop);
    resp_data.ordering_vector_len = htobe32((uint32_t)s->ext.tlsn_ordvec_len);
    resp_data.sig_len = htobe16((uint16_t)signed_data_len);

    unsigned int offset = 0;
    memcpy(response + offset, &message_type, TLSN_MESSAGE_TYPE_SIZE);
    offset += TLSN_MESSAGE_TYPE_SIZE;
    memcpy(response + offset, &resp_data, RESPONSE_DATA_SIZE);
    offset += RESPONSE_DATA_SIZE;
    memcpy(response + offset, signed_data, signed_data_len);
    offset += signed_data_len;
    memcpy(response + offset, s->ext.tlsn_ordvec,
           roundup(s->ext.tlsn_ordvec_len, 8));
    offset += roundup(s->ext.tlsn_ordvec_len, 8);

    if (offset != resp_len) {
        goto err;
    }

    size_t written;
    int r;
    while ((r =
            s->method->ssl_write_bytes(s, SSL3_RT_TLSN_MESSAGE, response,
                                       resp_len, &written)) < 0) {
        if (check_availability(s, r) < 0)
            goto err;
    }

    OPENSSL_free(response);
    EVP_PKEY_CTX_free(pkctx);
    OPENSSL_free(signed_data);
    OPENSSL_free(hashed_data);
    s->ext.tlsn_sent_responses++;
    return 1;

 err:
    OPENSSL_free(response);
    EVP_PKEY_CTX_free(pkctx);
    OPENSSL_free(signed_data);
    OPENSSL_free(hashed_data);
    return 0;
}

static int add_plaintextnode_to_tlsnproof(SSL *s, size_t *proof_offset_ptr,
                                          TLSN_CLIENT_RECORDING * curr_record,
                                          unsigned int received)
{

    uint64_t proof_offset = *proof_offset_ptr;

    PROOF_NODE proof_node;
    proof_node.node_type = plaintext_node;

    PLAINTEXT_PROOF_NODE curr_node;
    curr_node.gen_orig = received;
    curr_node.len_record = htobe16((uint16_t)curr_record->plaintext_size);

    unsigned char *proof_str = s->ext.tlsn_proof;
    s->ext.tlsn_proof_len +=
        PROOF_NODE_SIZE + PLAINTEXT_PROOF_NODE_SIZE +
        curr_record->plaintext_size + s->ext.salt_size;
    proof_str =
        (unsigned char *)OPENSSL_realloc(proof_str, s->ext.tlsn_proof_len);
    encode_nbo(proof_node.node_type, PROOF_NODE_SIZE, proof_str + proof_offset);
    proof_offset += PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, &curr_node, PLAINTEXT_PROOF_NODE_SIZE);
    proof_offset += PLAINTEXT_PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, curr_record->plaintext,
           curr_record->plaintext_size);
    proof_offset += curr_record->plaintext_size;
    memcpy(proof_str + proof_offset, curr_record->salt_secret,
           s->ext.salt_size);
    proof_offset += s->ext.salt_size;

    if (proof_offset != s->ext.tlsn_proof_len) {
        s->ext.tlsn_proof = proof_str;
        return 0;
    }

    s->ext.tlsn_proof = proof_str;
    *proof_offset_ptr = proof_offset;

    return 1;
}

/* Appends all the records to the proof as plaintext nodes */
static int create_plaintext_tlsnproof(SSL *s, size_t *proof_offset_ptr,
                                      size_t *num_proof_nodes_ptr)
{
    unsigned int record_index;
    unsigned int received;
    unsigned int recvd_index = 0;
    unsigned int sent_index = 0;
    TLSN_CLIENT_RECORDING *curr_record = NULL;

    if (s->ext.tlsn_client_recv_len == 0 && s->ext.tlsn_client_sent_len == 0)
        return 0;

    for (record_index = 0; record_index < s->ext.tlsn_proof_ordvec_len;
         record_index++) {

        received =
            (s->ext.
             tlsn_proof_ordvec[record_index / 8] >> (record_index % 8)) & 1;
        curr_record =
            received ? &(s->ext.tlsn_client_recv[recvd_index]) : &(s->ext.
                                                                   tlsn_client_sent
                                                                   [sent_index]);

        if (received) {
            recvd_index++;
        } else {
            sent_index++;
        }

        if (add_plaintextnode_to_tlsnproof
            (s, proof_offset_ptr, curr_record, received) <= 0)
            return 0;
        (*num_proof_nodes_ptr)++;
    }

    return 1;
}

static int check_response(SSL *s, uint32_t offset, uint32_t len,
                          RESPONSE_DATA resp_data)
{

    if (offset != len)
        return 0;

    if (be64toh(resp_data.timestamp_stop) < be64toh(resp_data.timestamp_start))
        return 0;

    size_t ord_vector_len =
        be32toh(resp_data.ordering_vector_len) +
        s->ext.tlsn_exchanged_ordvec * MAX_ORD_VECTOR_LEN;

    if (ord_vector_len !=
        s->ext.tlsn_client_recv_len + s->ext.tlsn_client_sent_len)
        return 0;

    return 1;
}

static void add_cert_chain_to_proof_buffer(SSL *s, PROOF_BUFFER * proof_buf_ptr)
{
    unsigned int i = 0;
    STACK_OF (X509) * peer_cert_chain = SSL_get_peer_cert_chain(s);
    uint16_t cert_num = sk_X509_num(peer_cert_chain);
    X509 *x;                    /*helping variable to store certificates when retrieved */
    size_t cert_chain_len = 0;

    for (i = 0; i < cert_num; i++) {
        x = sk_X509_value(peer_cert_chain, i);
        cert_chain_len += i2d_X509(x, NULL);
    }
    ((PROOF_PAR *) (proof_buf_ptr->buf))->cert_chain_len =
        htobe16(cert_chain_len);
    proof_buf_ptr->buf =
        OPENSSL_realloc(proof_buf_ptr->buf,
                        proof_buf_ptr->buf_len + cert_chain_len);
    proof_buf_ptr->buf_len += cert_chain_len;

    proof_buf_ptr->buf += proof_buf_ptr->offset;
    for (i = 0; i < cert_num; i++) {
        x = sk_X509_value(peer_cert_chain, i);
        proof_buf_ptr->offset += i2d_X509(x, &(proof_buf_ptr->buf));
    }
    proof_buf_ptr->buf -= proof_buf_ptr->offset;
}

/* Includes the certificate chain in the proof */
static void add_cert_chain_to_tlsnproof(SSL *s, size_t *proof_offset_ptr)
{
    unsigned int i = 0;
    STACK_OF (X509) * peer_cert_chain = SSL_get_peer_cert_chain(s);
    uint16_t cert_num = sk_X509_num(peer_cert_chain);
    X509 *x;                    /*helping variable to store certificates when retrieved */
    size_t cert_chain_len = 0;

    for (i = 0; i < cert_num; i++) {
        x = sk_X509_value(peer_cert_chain, i);
        cert_chain_len += i2d_X509(x, NULL);
    }
    ((PROOF_PAR *) s->ext.tlsn_proof)->cert_chain_len = htobe16(cert_chain_len);
    s->ext.tlsn_proof =
        OPENSSL_realloc(s->ext.tlsn_proof, *proof_offset_ptr + cert_chain_len);
    s->ext.tlsn_proof_len += cert_chain_len;

    s->ext.tlsn_proof += *proof_offset_ptr;
    for (i = 0; i < cert_num; i++) {
        x = sk_X509_value(peer_cert_chain, i);
        *proof_offset_ptr += i2d_X509(x, &s->ext.tlsn_proof);
    }
    s->ext.tlsn_proof -= *proof_offset_ptr;
}

/*controls that the tlsn_proof_ordvec (the ordering vector sent by the server)
 * comparing it to the tlsn_ordvec (the ordering vector registered by
 * the client).
 */
static int check_tlsn_proof_ordvec(SSL *s)
{
    if (s->ext.tlsn_proof_ordvec_len != s->ext.tlsn_ordvec_len)
        return -1;

    size_t i;
    size_t zeros_in_proof_ordvec = 0;
    size_t zeros_in_ordvec = 0;

    for (i = 0; i < s->ext.tlsn_proof_ordvec_len; i++) {

        if (((s->ext.tlsn_proof_ordvec[i / 8] >> (i % 8)) & 1) == 0)
            zeros_in_proof_ordvec++;

        if (((s->ext.tlsn_ordvec[i / 8] >> (i % 8)) & 1) == 0)
            zeros_in_ordvec++;

        /*At no point the server can claim having received
         * more messages then the client has sent.
         */
        if (zeros_in_proof_ordvec > zeros_in_ordvec)
            return -1;
    }

    if (zeros_in_proof_ordvec != zeros_in_ordvec)
        return -1;

    return 1;
}

/*This function not only builds the proof, but it
 * also checks that the response is well formed
 */
static int tlsn_handle_message_response(SSL *s, unsigned char *response,
                                        size_t len)
{
    s->ext.tlsn_received_responses++;
    uint32_t offset = 0;
    RESPONSE_DATA resp_data;
    unsigned char *sig_data;
    uint16_t sig_len;
    size_t proof_offset = 0;
    size_t prev_ord_vector_len =
        s->ext.tlsn_exchanged_ordvec * MAX_ORD_VECTOR_LEN;

    if (SSL_get_negotiated(s) == 0)
        return 0;

    /*retrieve received data */
    offset += TLSN_MESSAGE_TYPE_SIZE;
    memcpy(&resp_data, response + offset, RESPONSE_DATA_SIZE);
    offset += RESPONSE_DATA_SIZE;
    sig_len = be16toh(resp_data.sig_len);
    s->ext.tlsn_proof_ordvec_len =
        prev_ord_vector_len + be32toh(resp_data.ordering_vector_len);
    sig_data = response + offset;
    offset += sig_len;
    s->ext.tlsn_proof_ordvec =
        OPENSSL_realloc(s->ext.tlsn_proof_ordvec,
                        roundup(s->ext.tlsn_proof_ordvec_len, 8));
    memcpy(s->ext.tlsn_proof_ordvec + prev_ord_vector_len / 8,
           response + offset, roundup(s->ext.tlsn_proof_ordvec_len,
                                      8) - prev_ord_vector_len / 8);
    offset += roundup(be32toh(resp_data.ordering_vector_len), 8);

    if (check_response(s, offset, len, resp_data) <= 0) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE_RESPONSE, SSL_R_INVALID_RESPONSE);
        return 0;
    }

    if (check_tlsn_proof_ordvec(s) <= 0) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE_RESPONSE,
               SSL_R_INVALID_ORDERING_VECTOR);
        return -1;
    }

    /* Construct the first part of proof */
    PROOF_PAR proofPar = { 0 };
    proofPar.tlsn_version = s->ext.tlsn_version;
    proofPar.hash_type = from_evpmd_to_hashalg(ssl_handshake_md(s));
    proofPar.salt_size = htobe16((uint16_t)s->ext.salt_size);
    proofPar.chunk_size = htobe16((uint16_t)s->ext.chunk_size);
    proofPar.start_time = resp_data.timestamp_start;
    proofPar.stop_time = resp_data.timestamp_stop;
    proofPar.sig_len = resp_data.sig_len;
    proofPar.num_proof_nodes = 0;
    proofPar.cert_chain_len = 0; //the certificate chain will be added later*/

    /* Allocate proof string */
    s->ext.tlsn_proof_len = PROOF_PAR_SIZE + sig_len;
    s->ext.tlsn_proof =
        (unsigned char *)OPENSSL_realloc(s->ext.tlsn_proof,
                                         s->ext.tlsn_proof_len);
    if (s->ext.tlsn_proof == NULL)
        return 0;

    memcpy(s->ext.tlsn_proof + proof_offset, (unsigned char *)&proofPar,
           PROOF_PAR_SIZE);
    proof_offset += PROOF_PAR_SIZE;
    memcpy(s->ext.tlsn_proof + proof_offset, sig_data, sig_len);
    proof_offset += sig_len;

    if (s->ext.request_option == INCLUDE_CERT_CHAIN)
        add_cert_chain_to_tlsnproof(s, &proof_offset);

    if ((size_t)(proof_offset) != s->ext.tlsn_proof_len)
        goto err;

    /*append records to the proof */
    size_t num_proof_nodes = 0;
    if (create_plaintext_tlsnproof(s, &proof_offset, &num_proof_nodes) <= 0)
        goto err;

    ((PROOF_PAR *) s->ext.tlsn_proof)->num_proof_nodes =
        htonl((uint32_t)num_proof_nodes);

    return 1;
 err:
    return 0;
}

static int tlsn_handle_message_ord_vector(SSL *s, unsigned char *data,
                                          size_t len)
{
    if (len != MAX_ORD_VECTOR_LEN / 8 + 1)
        return -1;
    if (*data != tlsn_message_type_ordering_vector)
        return -1;

    size_t ord_vector_bytes =
        s->ext.tlsn_exchanged_ordvec * (MAX_ORD_VECTOR_LEN / 8);
    size_t vector_offset =
        ord_vector_bytes >
        (s->ext.tlsn_proof_ordvec_len /
         8) ? ord_vector_bytes : (s->ext.tlsn_proof_ordvec_len / 8);
    size_t data_offset =
        TLSN_MESSAGE_TYPE_SIZE + (vector_offset % (MAX_ORD_VECTOR_LEN / 8));
    size_t new_ord_vector_bytes =
        (s->ext.tlsn_exchanged_ordvec + 1) * (MAX_ORD_VECTOR_LEN / 8);

    s->ext.tlsn_proof_ordvec =
        OPENSSL_realloc(s->ext.tlsn_proof_ordvec, new_ord_vector_bytes);
    memcpy(s->ext.tlsn_proof_ordvec + vector_offset, data + data_offset,
           new_ord_vector_bytes - vector_offset);

    s->ext.tlsn_exchanged_ordvec++;
    return 1;

}

int tlsn_handle_message(SSL *s, unsigned char *data, size_t len)
{

    if (SSL_get_negotiated(s) != 1) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE, SSL_R_EXTENSION_NOT_NEGOTIATED);
        return -1;
    }

    if (SSL_get_salt_size(s) < MINIMUM_SALT_SIZE
        || SSL_get_salt_size(s) > MAXIMUM_SALT_SIZE
        || SSL_get_chunk_size(s) < MINIMUM_CHUNK_SIZE
        || SSL_get_chunk_size(s) > MAXIMUM_CHUNK_SIZE) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE,
               SSL_R_SALT_OR_CHUNK_SIZE_NOT_CORRECTLY_NEGOTIATED);
        return -1;
    }

    if (!(*data == tlsn_message_type_request && s->server)
        && !(*data == tlsn_message_type_response && !s->server)
        && !(*data == tlsn_message_type_ordering_vector && !s->server)) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE, SSL_R_INVALID_MESSAGE);
        return -1;
    }

    if ((len != TLSN_MESSAGE_TYPE_SIZE && *data == tlsn_message_type_request)
        || (len == 0 && *data == tlsn_message_type_response)
        || (len != MAX_ORD_VECTOR_LEN / 8 + 1
            && *data == tlsn_message_type_ordering_vector)) {
        SSLerr(SSL_F_TLSN_HANDLE_MESSAGE, SSL_R_INVALID_MESSAGE);
        return -1;
    }

    switch (*data) {
    case tlsn_message_type_request:

        if (tlsn_handle_message_request(s) <= 0)
            return -1;
        break;

    case tlsn_message_type_response:
        if (tlsn_handle_message_response(s, data, len) <= 0)
            return -1;
        break;

    case tlsn_message_type_ordering_vector:
        if (tlsn_handle_message_ord_vector(s, data, len) <= 0)
            return -1;
        break;

    default:

        return -1;
        break;
    }

    return 1;
}

static int requester_control_proof_par(SSL *s, PROOF_PAR proof_par)
{
    uint16_t hash_size =
        EVP_MD_meth_get_result_size(from_hashalg_to_evpmd(proof_par.hash_type));

    if (hash_size > EVP_MAX_MD_SIZE
        || be16toh(proof_par.salt_size) < MINIMUM_SALT_SIZE
        || be16toh(proof_par.salt_size) > MAXIMUM_SALT_SIZE
        || be16toh(proof_par.chunk_size) < MINIMUM_CHUNK_SIZE
        || be16toh(proof_par.chunk_size) > MAXIMUM_CHUNK_SIZE
        || be64toh(proof_par.stop_time) < be64toh(proof_par.start_time))
        return 0;

    if (be32toh(proof_par.num_proof_nodes)
        > s->ext.tlsn_proof_ordvec_len)
        return 0;

    return 1;
}

static uint16_t compute_compressed_record_length(RECORD_PROOF_INFO * rpi)
{
    int j;
    uint16_t compressed_record_length = rpi->buf_length;

    /* Subtract the size for censored chunks */
    for (j = 0; j < rpi->num_hidden_chunks; ++j) {
        compressed_record_length -=
            get_chunk_length2(rpi, rpi->hidden_chunks_ids[j]);
    }

    return compressed_record_length;
}

static int compute_proof_salts2(RECORD_PROOF_INFO * rpi, const int level,
                                unsigned char *int_salt_secret,
                                int *nonsensitive_subtree,
                                PROOF_SALT_LOC * nonsense_loc,
                                unsigned char *hash_for_nonsense)
{
    unsigned char new_salt[2 * (rpi->salt_size)];
    size_t new_salt_len = 2 * (rpi->salt_size);
    unsigned char *left;
    unsigned char *right;
    int left_nonsensitive;
    int right_nonsensitive;
    PROOF_SALT_LOC left_loc;
    PROOF_SALT_LOC right_loc;
    unsigned char left_hash_for_nonsense[rpi->salt_size];
    unsigned char right_hash_for_nonsense[rpi->salt_size];
    uint16_t orig_salt_index = rpi->salt_index;

    if (rpi->salt_index >= rpi->num_chunks) {
        return 1;
    }

    /* This should never happen, it must be handed separatedly */
    if (rpi->num_chunks == 1)
        return 0;

    if (compute_hkdf_expansion
        (rpi->hash_type, int_salt_secret, rpi->salt_size, SALT_TREE_LABEL,
         SALTTREE_LABEL_LEN, NULL, 0, new_salt, new_salt_len) < 1)
        return 0;

    // Split into left and right
    left = new_salt;
    right = new_salt + rpi->salt_size;

    // Leaf Detection: A leaf is on the last level or is within the last two indices
    if (level == rpi->tree_levels - 1) {

        left_nonsensitive =
            !is_hidden_chunk(rpi->hidden_chunks_ids, rpi->num_hidden_chunks,
                             rpi->salt_index);

        if (rpi->salt_index + 1 >= rpi->num_chunks) {
            *nonsensitive_subtree = left_nonsensitive;
            nonsense_loc->salt_index = rpi->salt_index;
            nonsense_loc->tree_level = level + 1;
            memcpy(hash_for_nonsense, left, rpi->salt_size);
            rpi->salt_index += 1;
            return 1;
        }

        right_nonsensitive =
            !is_hidden_chunk(rpi->hidden_chunks_ids, rpi->num_hidden_chunks,
                             rpi->salt_index + 1);

        // If both are not hidden, push it up
        if (left_nonsensitive && right_nonsensitive) {
            *nonsensitive_subtree = 1;
            nonsense_loc->tree_level = level;
            nonsense_loc->salt_index = rpi->salt_index;
            memcpy(hash_for_nonsense, int_salt_secret, rpi->salt_size);
            rpi->salt_index += 2;
            return 1;
        }
        *nonsensitive_subtree = 0;

        if (left_nonsensitive) {
            rpi->salt_locs =
                OPENSSL_realloc(rpi->salt_locs,
                                (rpi->num_salts + 1) * sizeof(PROOF_SALT_LOC));
            rpi->salt_locs[rpi->num_salts].tree_level = htobe16(level + 1);
            rpi->salt_locs[rpi->num_salts].salt_index =
                htobe16(rpi->salt_index);
            memcpy(rpi->salts[rpi->num_salts], left, rpi->salt_size);
            rpi->num_salts++;
        }
        rpi->salt_index += 1;

        if (right_nonsensitive) {
            rpi->salt_locs =
                OPENSSL_realloc(rpi->salt_locs,
                                (rpi->num_salts + 1) * sizeof(PROOF_SALT_LOC));
            rpi->salt_locs[rpi->num_salts].tree_level = htobe16(level + 1);
            rpi->salt_locs[rpi->num_salts].salt_index =
                htobe16(rpi->salt_index);
            memcpy(rpi->salts[rpi->num_salts], right, rpi->salt_size);
            rpi->num_salts++;
        }
        rpi->salt_index += 1;

        if (rpi->salt_index > rpi->num_chunks)
            return 0;

    } else {

        /* Go to lower level */
        if (compute_proof_salts2
            (rpi, level + 1, left, &left_nonsensitive, &left_loc,
             left_hash_for_nonsense) <= 0)
            return 0;

        if (rpi->salt_index >= rpi->num_chunks) {

            if (left_nonsensitive) {
                /* If only left is around, push it up */
                *nonsensitive_subtree = 1;
                nonsense_loc->tree_level = left_loc.tree_level;
                nonsense_loc->salt_index = left_loc.salt_index;
                memcpy(hash_for_nonsense, left_hash_for_nonsense,
                       rpi->salt_size);
            } else {
                *nonsensitive_subtree = 0;
            }

            return 1;
        }

        if (compute_proof_salts2
            (rpi, level + 1, right, &right_nonsensitive, &right_loc,
             right_hash_for_nonsense) <= 0)
            return 0;

        /* Merge the two sides */
        if (left_nonsensitive && right_nonsensitive) {
            /* both not hidden */
            *nonsensitive_subtree = 1;
            nonsense_loc->tree_level = level;
            nonsense_loc->salt_index = orig_salt_index;
            memcpy(hash_for_nonsense, int_salt_secret, rpi->salt_size);
        } else {
            *nonsensitive_subtree = 0;
            if (left_nonsensitive) {
                memcpy(rpi->salts[rpi->num_salts], left_hash_for_nonsense,
                       rpi->salt_size);
                rpi->salt_locs =
                    OPENSSL_realloc(rpi->salt_locs,
                                    (rpi->num_salts +
                                     1) * sizeof(PROOF_SALT_LOC));
                rpi->salt_locs[rpi->num_salts].salt_index =
                    htobe16(left_loc.salt_index);
                rpi->salt_locs[rpi->num_salts].tree_level =
                    htobe16(left_loc.tree_level);
                rpi->num_salts++;
            } else if (right_nonsensitive) {
                memcpy(rpi->salts[rpi->num_salts], right_hash_for_nonsense,
                       rpi->salt_size);
                rpi->salt_locs =
                    OPENSSL_realloc(rpi->salt_locs,
                                    (rpi->num_salts +
                                     1) * sizeof(PROOF_SALT_LOC));
                rpi->salt_locs[rpi->num_salts].salt_index =
                    htobe16(right_loc.salt_index);
                rpi->salt_locs[rpi->num_salts].tree_level =
                    htobe16(right_loc.tree_level);
                rpi->num_salts++;
            }
        }
    }

    return 1;
}

static int compute_proof_salts(RECORD_PROOF_INFO * rpi,
                               unsigned char *int_salt_secret)
{
    int sensitive_subtree;
    rpi->num_salts = 0;
    rpi->salt_index = 0;
    rpi->salt_locs = NULL;

    return compute_proof_salts2(rpi, 0, int_salt_secret, &sensitive_subtree,
                                NULL, NULL);
}

static unsigned char **reallocate_string_array(unsigned char **string_array,
                                               size_t string_size,
                                               size_t num_strings)
{
    unsigned int i;
    unsigned char **tmp = string_array;

    /*allocate the vector of salts-pointers */
    string_array =
        (unsigned char **)OPENSSL_realloc(string_array,
                                          sizeof(unsigned char *) *
                                          num_strings);
    if (string_array == NULL)
        return NULL;

    /* Allocate salts */
    if (tmp == NULL) {
        string_array[0] =
            (unsigned char *)OPENSSL_malloc(string_size * num_strings);
    } else {
        string_array[0] =
            (unsigned char *)OPENSSL_realloc(string_array[0],
                                             string_size * num_strings);
    }
    if (string_array[0] == NULL)
        return NULL;

    /*give the pointers the adresses of the salts */
    for (i = 1; i < num_strings; ++i) {
        string_array[i] = string_array[i - 1] + string_size;
    }
    return string_array;
}

/* outbuf has to be of length hash_size */
static int compute_proof_merkle_hashes2(RECORD_PROOF_INFO * rpi, int level,
                                        unsigned char *outbuf, int *am_hidden,
                                        PROOF_HASH_LOC * hidden_loc)
{
    unsigned int hash_size = rpi->hash_size;
    uint8_t left_child[rpi->hash_size];
    uint8_t right_child[rpi->hash_size];
    int left_hidden;
    int right_hidden;
    PROOF_HASH_LOC left_loc;
    PROOF_HASH_LOC right_loc;
    uint16_t orig_chunk_index = rpi->chunk_index;

    if (rpi->chunk_index >= rpi->num_chunks) {
        *am_hidden = 0;
        return 1;
    }
    // Check if this a leaf
    if (level == rpi->tree_levels) {
        if (is_hidden_chunk
            (rpi->hidden_chunks_ids, rpi->num_hidden_chunks,
             rpi->chunk_index)) {

            size_t chunk_length = get_chunk_length(rpi);

            /* Compute hash from salt and chunk */
            if (1 != EVP_DigestInit_ex(rpi->mdctx, rpi->hash_type, NULL)
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         rpi->salts[rpi->chunk_index],
                                         rpi->salt_size)
                || 1 != EVP_DigestUpdate(rpi->mdctx,
                                         &(rpi->
                                           buf[rpi->chunk_size *
                                               rpi->chunk_index]),
                                         chunk_length))
                return 0;

            /* Special case Root node: this should never happen. A completely hidden node should be a merkle_hash_node */
            if (level == 0)
                return 0;

            if (1 != EVP_DigestFinal_ex(rpi->mdctx, outbuf, &hash_size))
                return 0;

            *am_hidden = 1;
            hidden_loc->tree_level = level;
            hidden_loc->chunk_index = rpi->chunk_index;
        } else {
            *am_hidden = 0;
        }

        rpi->chunk_index += 1;
        return 1;
    } else {

        /* left side */
        if (compute_proof_merkle_hashes2
            (rpi, level + 1, left_child, &left_hidden, &left_loc) <= 0)
            return 0;

        /* If we don't need the right side any more, just push the left side upwards */
        if (rpi->chunk_index >= rpi->num_chunks) {
            *am_hidden = left_hidden;
            if (left_hidden) {
                memcpy(outbuf, left_child, rpi->hash_size);
                hidden_loc->tree_level = level;
                hidden_loc->chunk_index = left_loc.chunk_index;
            }
            return 1;
        }

        /* right side */
        if (compute_proof_merkle_hashes2
            (rpi, level + 1, right_child, &right_hidden, &right_loc) <= 0)
            return 0;

        /* Compute hash for current node */
        *am_hidden = right_hidden && left_hidden;

        if (*am_hidden) {
            if (1 != EVP_DigestInit_ex(rpi->mdctx, rpi->hash_type, NULL)
                || 1 != EVP_DigestUpdate(rpi->mdctx, left_child, rpi->hash_size)
                || 1 != EVP_DigestUpdate(rpi->mdctx, right_child,
                                         rpi->hash_size))
                return 0;

            /* Special case Root node: this should never happen. A completely hidden node should be a merkle_hash_node */
            if (level == 0)
                return 0;

            if (1 != EVP_DigestFinal_ex(rpi->mdctx, outbuf, &hash_size))
                return 0;

            hidden_loc->tree_level = level;
            hidden_loc->chunk_index = orig_chunk_index;

        } else if (left_hidden) {
            rpi->hash_locs[rpi->num_hashes].tree_level =
                htobe16(left_loc.tree_level);
            rpi->hash_locs[rpi->num_hashes].chunk_index =
                htobe16(left_loc.chunk_index);
            rpi->proof_merkle_hashes =
                reallocate_string_array(rpi->proof_merkle_hashes,
                                        rpi->hash_size, rpi->num_hashes + 1);
            memcpy(rpi->proof_merkle_hashes[rpi->num_hashes], left_child,
                   rpi->hash_size);
            rpi->num_hashes += 1;
        } else if (right_hidden) {
            rpi->hash_locs[rpi->num_hashes].tree_level =
                htobe16(right_loc.tree_level);
            rpi->hash_locs[rpi->num_hashes].chunk_index =
                htobe16(right_loc.chunk_index);
            rpi->proof_merkle_hashes =
                reallocate_string_array(rpi->proof_merkle_hashes,
                                        rpi->hash_size, rpi->num_hashes + 1);
            memcpy(rpi->proof_merkle_hashes[rpi->num_hashes], right_child,
                   rpi->hash_size);
            rpi->num_hashes += 1;
        }

        return 1;
    }
}

static int compute_proof_merkle_hashes(RECORD_PROOF_INFO * rpi)
{
    if (rpi->hash_locs == NULL) {
        rpi->hash_locs =
            (PROOF_HASH_LOC *) OPENSSL_malloc(rpi->num_hidden_chunks *
                                              sizeof(PROOF_HASH_LOC));
        if (rpi->hash_locs == NULL)
            return 0;
    }

    rpi->num_hashes = 0;
    rpi->chunk_index = 0;

    int am_hidden;              /*it is 1 if the currently processed node is a hidden node */
    if (compute_proof_merkle_hashes2(rpi, 0, NULL, &am_hidden, NULL) <= 0)
        return 0;

    if (rpi->chunk_index != rpi->num_chunks)
        return 0;
    if (am_hidden)
        return 0;

    return 1;
}

static int assign_sens_chunks_to_rpi(RECORD_PROOF_INFO * rpi,
                                     uint16_t *hidden_chunks_ids,
                                     size_t num_hidden_chunks)
{
    size_t k;
    rpi->num_hidden_chunks = num_hidden_chunks;
    rpi->hidden_chunks_ids =
        (uint16_t *)OPENSSL_malloc(rpi->num_hidden_chunks * sizeof(uint16_t));
    if (rpi->hidden_chunks_ids == NULL)
        return -1;

    for (k = 0; k < num_hidden_chunks; k++)
        (rpi->hidden_chunks_ids)[k] = hidden_chunks_ids[k];

    return 1;
}

/* writes the indices of the sensitive chunks of record i in hidden_chunks_ids */
static int find_sensitive_chunks(uint16_t num_chunks, int16_t **sens_mtrx,
                                 unsigned int i,
                                 uint16_t **hidden_chunks_ids_ptr,
                                 size_t *num_hidden_chunks_ptr)
{
    int k;

    for (k = 0; sens_mtrx[i][k] >= 0; k++) {

        if (sens_mtrx[i][k] >= num_chunks) {
            SSLerr(SSL_F_FIND_SENSITIVE_CHUNKS,
                   SSL_R_SENSITIVE_MATRIX_ELEMENT_GREATER_THEN_RECORDS_CHUNKS_NUMBER);
            return 0;
        }

        if (is_hidden_chunk
            (*hidden_chunks_ids_ptr, *num_hidden_chunks_ptr, sens_mtrx[i][k])) {
            SSLerr(SSL_F_FIND_SENSITIVE_CHUNKS,
                   SSL_R_REPEATED_ELEMENT_IN_SENSITIVE_MATRIX);
            return 0;
        }
        *hidden_chunks_ids_ptr =
            (uint16_t *)OPENSSL_realloc(*hidden_chunks_ids_ptr,
                                        (*num_hidden_chunks_ptr +
                                         1) * sizeof(uint16_t));
        (*hidden_chunks_ids_ptr)[*num_hidden_chunks_ptr] = sens_mtrx[i][k];
        (*num_hidden_chunks_ptr)++;
    }

    switch (sens_mtrx[i][k]) {

    case -2:
        if (k != 0) {
            SSLerr(SSL_F_FIND_SENSITIVE_CHUNKS,
                   SSL_R_INVALID_POSITION_FOR_NEGATIVE_NUMBER);
            return 0;
        }

        *hidden_chunks_ids_ptr =
            (uint16_t *)OPENSSL_realloc(*hidden_chunks_ids_ptr,
                                        num_chunks * sizeof(uint16_t));
        for (k = 0; k < num_chunks; k++)
            (*hidden_chunks_ids_ptr)[k] = k;
        *num_hidden_chunks_ptr = num_chunks;
        break;

    case -1:
        break;

    default:
        SSLerr(SSL_F_FIND_SENSITIVE_CHUNKS, SSL_R_INVALID_NEGATIVE_NUMBER);
        return 0;
    }
    return 1;

}

static int add_plaintext_proof_node(SSL *s, PROOF_BUFFER * proof_buffer_ptr,
                                    TLSN_CLIENT_RECORDING * curr_record,
                                    unsigned int received)
{

    uint64_t proof_offset = proof_buffer_ptr->offset;

    PROOF_NODE proof_node;
    proof_node.node_type = plaintext_node;

    PLAINTEXT_PROOF_NODE curr_node;
    curr_node.gen_orig = received;
    curr_node.len_record = htobe16((uint16_t)curr_record->plaintext_size);
    unsigned char *proof_str = proof_buffer_ptr->buf;
    proof_buffer_ptr->buf_len +=
        PROOF_NODE_SIZE + PLAINTEXT_PROOF_NODE_SIZE +
        curr_record->plaintext_size + s->ext.salt_size;
    proof_str =
        (unsigned char *)OPENSSL_realloc(proof_str, proof_buffer_ptr->buf_len);
    encode_nbo(proof_node.node_type, PROOF_NODE_SIZE, proof_str + proof_offset);
    proof_offset += PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, &curr_node, PLAINTEXT_PROOF_NODE_SIZE);
    proof_offset += PLAINTEXT_PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, curr_record->plaintext,
           curr_record->plaintext_size);
    proof_offset += curr_record->plaintext_size;
    memcpy(proof_str + proof_offset, curr_record->salt_secret,
           s->ext.salt_size);
    proof_offset += s->ext.salt_size;

    if (proof_offset != proof_buffer_ptr->buf_len) {
        proof_buffer_ptr->buf = proof_str;
        return 0;
    }

    proof_buffer_ptr->buf = proof_str;
    proof_buffer_ptr->offset = proof_offset;
    return 1;
}

static int add_merkle_proof_node(SSL *s, PROOF_BUFFER * proof_buffer_ptr,
                                 unsigned char *merkle_hash, size_t hash_size)
{

    uint64_t proof_offset = proof_buffer_ptr->offset;

    PROOF_NODE proof_node;
    proof_node.node_type = merkle_hash_node;

    unsigned char *proof_str = proof_buffer_ptr->buf;

    proof_buffer_ptr->buf_len += PROOF_NODE_SIZE + hash_size;
    proof_str =
        (unsigned char *)OPENSSL_realloc(proof_str, proof_buffer_ptr->buf_len);
    encode_nbo(proof_node.node_type, PROOF_NODE_SIZE, proof_str + proof_offset);
    proof_offset += PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, merkle_hash, hash_size);
    proof_offset += hash_size;

    if (proof_offset != proof_buffer_ptr->buf_len)
        return 0;

    proof_buffer_ptr->buf = proof_str;
    proof_buffer_ptr->offset = proof_offset;
    return 1;
}

/* computes the merkle root of curr_record and stores it into curr_record->merkle_hash */
static int compute_merkle_root(SSL *s, RECORD_PROOF_INFO ** rpi_ptr,
                               TLSN_CLIENT_RECORDING * curr_record,
                               int received, size_t hash_size)
{

    *rpi_ptr =
        init_rpi(s, curr_record->plaintext, curr_record->plaintext_size,
                 received);
    if (*rpi_ptr == NULL)
        return 0;

    /*Compute merkle hash if not precomputed */
    if (curr_record->merkle_hash == NULL) {
        curr_record->merkle_hash = (unsigned char *)OPENSSL_malloc(hash_size);

        if (compute_salt_tree(*rpi_ptr, curr_record->salt_secret) <= 0)
            goto err;

        if (compute_merkle_tree(*rpi_ptr, curr_record->merkle_hash) <= 0)
            goto err;
    }

    return 1;
 err:
    return -1;
}

/* appends the node of the current record to proof_buf */
static int append_current_record_to_proof_buf(SSL *s,
                                              PROOF_BUFFER * proof_buf_ptr,
                                              TLSN_CLIENT_RECORDING *
                                              curr_record,
                                              unsigned int received,
                                              size_t record_index,
                                              size_t *num_proof_nodes_ptr,
                                              int16_t **sens_mtrx)
{

    size_t hash_size = (size_t)EVP_MD_meth_get_result_size(ssl_handshake_md(s));
    RECORD_PROOF_INFO *rpi = NULL;
    uint16_t *hidden_chunks_ids = NULL;
    size_t num_hidden_chunks;
    uint16_t num_chunks =
        roundup((uint64_t)curr_record->plaintext_size, SSL_get_chunk_size(s));
    num_hidden_chunks = 0;
    int j;

    if (find_sensitive_chunks
        (num_chunks, sens_mtrx, record_index, &hidden_chunks_ids,
         &num_hidden_chunks) <= 0)
        goto err;

    if (num_hidden_chunks == 0) {

        if (add_plaintext_proof_node(s, proof_buf_ptr, curr_record, received) <=
            0)
            goto err;
        (*num_proof_nodes_ptr)++;

    } else if (num_hidden_chunks == num_chunks) {

        if (compute_merkle_root(s, &rpi, curr_record, received, hash_size) <= 0)
            goto err;

        if (add_merkle_proof_node
            (s, proof_buf_ptr, curr_record->merkle_hash, hash_size) <= 0)
            goto err;

        (*num_proof_nodes_ptr)++;
    } else {
        /* Mixed Node */
        rpi =
            init_rpi(s, curr_record->plaintext, curr_record->plaintext_size,
                     received);
        if (rpi == NULL)
            goto err;

        if (assign_sens_chunks_to_rpi(rpi, hidden_chunks_ids, num_hidden_chunks)
            <= 0)
            goto err;

        /*salts are needed for computing the merkle tree */
        if (compute_salt_tree(rpi, curr_record->salt_secret) <= 0)
            goto err;

        if (compute_proof_merkle_hashes(rpi) <= 0)
            goto err;

        /* ----- Compute the proof salts ---- */
        if (compute_proof_salts(rpi, curr_record->salt_secret) <= 0)
            goto err;

        unsigned char **proof_salts = rpi->salts;

        /* ---- Form proof str ---- */
        PROOF_NODE proof_node;
        proof_node.node_type = hidden_plaintext_node;

        HIDDEN_PLAINTEXT_PROOF_NODE plaintext_proof_node;
        plaintext_proof_node.gen_orig = (uint8_t)received;
        plaintext_proof_node.len_record = be16toh(rpi->buf_length);
        plaintext_proof_node.num_salts = htobe16((uint16_t)rpi->num_salts);
        plaintext_proof_node.num_hashes = htobe16((uint16_t)rpi->num_hashes);

        if (proof_buf_ptr->offset != proof_buf_ptr->buf_len)
            goto err;

        /* appending: proof node struct, hidden plaintext proof node struct,
         * salt locs and salts, hash locs and hashes,
         * compressed (without censored chunks) record length)*/

        proof_buf_ptr->buf_len +=
            PROOF_NODE_SIZE + HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;
        proof_buf_ptr->buf_len +=
            rpi->num_salts * PROOF_SALT_LOC_SIZE +
            rpi->num_salts * rpi->salt_size;
        proof_buf_ptr->buf_len +=
            rpi->num_hashes * PROOF_MERKLE_LOC_SIZE +
            rpi->num_hashes * rpi->hash_size;
        proof_buf_ptr->buf_len += compute_compressed_record_length(rpi);
        proof_buf_ptr->buf =
            (unsigned char *)OPENSSL_realloc(proof_buf_ptr->buf,
                                             proof_buf_ptr->buf_len);

        memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset, &proof_node,
               PROOF_NODE_SIZE);
        proof_buf_ptr->offset += PROOF_NODE_SIZE;
        memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
               &plaintext_proof_node, HIDDEN_PLAINTEXT_PROOF_NODE_SIZE);
        proof_buf_ptr->offset += HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;

        for (j = 0; j < rpi->num_salts; ++j) {
            memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
                   &(rpi->salt_locs[j]), PROOF_SALT_LOC_SIZE);
            proof_buf_ptr->offset += PROOF_SALT_LOC_SIZE;
        }

        memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset, proof_salts[0],
               rpi->num_salts * rpi->salt_size);
        proof_buf_ptr->offset += rpi->num_salts * rpi->salt_size;

        for (j = 0; j < rpi->num_hashes; ++j) {
            memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
                   &(rpi->hash_locs[j]), PROOF_MERKLE_LOC_SIZE);
            proof_buf_ptr->offset += PROOF_MERKLE_LOC_SIZE;
        }

        memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
               rpi->proof_merkle_hashes[0], rpi->num_hashes * rpi->hash_size);
        proof_buf_ptr->offset += rpi->num_hashes * rpi->hash_size;
        /* Only include uncensored record parts */
        uint16_t chunk_index;
        uint16_t chunk_length;

        for (chunk_index = 0; chunk_index < rpi->num_chunks; ++chunk_index) {
            chunk_length = get_chunk_length2(rpi, chunk_index);

            if (!is_hidden_chunk
                (rpi->hidden_chunks_ids, rpi->num_hidden_chunks, chunk_index)) {
                memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
                       rpi->buf + chunk_index * rpi->chunk_size, chunk_length);
                proof_buf_ptr->offset += chunk_length;
            }
        }

        if (proof_buf_ptr->offset != proof_buf_ptr->buf_len)
            goto err;

        (*num_proof_nodes_ptr)++;
    }

    free_rpi(rpi);
    OPENSSL_free(hidden_chunks_ids);
    return 1;
 err:
    free_rpi(rpi);
    OPENSSL_free(hidden_chunks_ids);
    return 0;
}

/*compares two hidden chunks vecotr and verifies if they contain the same chunks*/
static int compare_hidden_chunks_vectors(uint16_t *hidden_chunks_ids,
                                         size_t num_hidden_chunks,
                                         uint16_t *hidden_chunks_ids_second,
                                         size_t num_hidden_chunks_second)
{
    if (num_hidden_chunks != num_hidden_chunks_second)
        return 0;

    size_t i;
    for (i = 0; i < num_hidden_chunks_second; i++) {
        if (is_hidden_chunk
            (hidden_chunks_ids, num_hidden_chunks,
             hidden_chunks_ids_second[i]) == 0)
            return 0;
    }
    return 1;
}

static void free_rpi_initialized_from_proof(RECORD_PROOF_INFO * rpi)
{

    if (rpi->hidden_chunks_ids != NULL) {
        OPENSSL_free(rpi->hidden_chunks_ids);
        rpi->hidden_chunks_ids = NULL;
    }
    if (rpi->mdctx != NULL) {
        EVP_MD_CTX_destroy(rpi->mdctx);
        rpi->mdctx = NULL;
    }
    if (rpi->salts != NULL) {
        OPENSSL_free(rpi->salts[0]);
        OPENSSL_free(rpi->salts);
        rpi->salts = NULL;
    }
    if (rpi->buf != NULL) {
        OPENSSL_free((unsigned char *)rpi->buf);
        rpi->buf = NULL;
    }
    OPENSSL_free(rpi);
    rpi = NULL;
}

/* Recompute the hidden chunks from the proof contents*/
static int compute_hidden_chunks_from_proof(RECORD_PROOF_INFO * rpi)
{
    int i;
    int j;
    uint16_t hidden_chunk_ids[rpi->num_chunks];
    uint16_t num_skipped;
    rpi->num_hidden_chunks = 0;
    for (i = 0; i < rpi->num_hashes; ++i) {
        num_skipped =
            num_skipped_leaves(rpi, be16toh(rpi->hash_locs[i].tree_level),
                               be16toh(rpi->hash_locs[i].chunk_index));
        for (j = 0; j < num_skipped; ++j) {
            // Save all the skipped leaves as hidden
            hidden_chunk_ids[rpi->num_hidden_chunks] =
                be16toh(rpi->hash_locs[i].chunk_index) + j;
            rpi->num_hidden_chunks++;
        }
    }
    if (rpi->num_hidden_chunks == 0) {
        rpi->hidden_chunks_ids = NULL;
    } else {
        rpi->hidden_chunks_ids =
            (uint16_t *)OPENSSL_malloc(rpi->num_hidden_chunks *
                                       sizeof(uint16_t));
        if (rpi->hidden_chunks_ids == NULL)
            return 0;
        memcpy(rpi->hidden_chunks_ids, hidden_chunk_ids,
               rpi->num_hidden_chunks * sizeof(uint16_t));

    }
    return 1;
}

/*Initializes the RecordProofInfo structure from the hidden plaintext proof node*/
static RECORD_PROOF_INFO *init_rpi_from_hidden_node(HIDDEN_PLAINTEXT_PROOF_NODE
                                                    * proof_node,
                                                    unsigned char *plaintext,
                                                    PROOF_HASH_LOC * hash_locs,
                                                    unsigned char
                                                    **proof_hashes,
                                                    PROOF_SALT_LOC * salt_locs,
                                                    size_t salt_size,
                                                    size_t chunk_size,
                                                    const EVP_MD *hash_type)
{
    RECORD_PROOF_INFO rpival = {.salt_size = salt_size,
        .hash_type = hash_type,
        .hash_size = EVP_MD_meth_get_result_size(rpival.hash_type),
        .chunk_size = chunk_size,
        .num_chunks =
            (uint16_t)roundup(be16toh(proof_node->len_record),
                              rpival.chunk_size),
        .tree_levels = (uint16_t)logb2(rpival.num_chunks),
        .gen_orig = (unsigned char)proof_node->gen_orig
    };
    rpival.buf_length = be16toh(proof_node->len_record);
    rpival.salt_index = 0;
    rpival.chunk_index = 0;
    rpival.num_hashes = be16toh(proof_node->num_hashes);
    rpival.hash_locs = hash_locs;
    rpival.proof_merkle_hashes = proof_hashes;
    rpival.salt_locs = salt_locs;
    rpival.num_salts = be16toh(proof_node->num_salts);
    rpival.init_from_proof = 1;
    rpival.mdctx = EVP_MD_CTX_create();

    // Copy, do this to allow const values
    RECORD_PROOF_INFO *rpi =
        (RECORD_PROOF_INFO *) OPENSSL_malloc(sizeof(RECORD_PROOF_INFO));
    memcpy(rpi, &rpival, sizeof(rpival));
    rpi->salts = allocate_string_array(rpi->salt_size, rpi->num_chunks);
    if (rpi->salts == NULL)
        return NULL;

    if (rpi->num_hashes > 0) {
        if (compute_hidden_chunks_from_proof(rpi) < 1)
            return NULL;
    } else {
        rpi->hidden_chunks_ids = NULL;
        rpi->num_hidden_chunks = 0;
    }
    rpi->buf = OPENSSL_malloc(rpi->buf_length);

    return rpi;
}

/*Initializes the RecordProofInfo structure from the plaintext proof node*/
static RECORD_PROOF_INFO *init_rpi_from_plaintext_node(PLAINTEXT_PROOF_NODE *
                                                       proof_node,
                                                       unsigned char *plaintext,
                                                       size_t salt_size,
                                                       size_t chunk_size,
                                                       const EVP_MD *hash_type)
{

    RECORD_PROOF_INFO rpival = {.salt_size = salt_size,
        .hash_type = hash_type,
        .hash_size = EVP_MD_meth_get_result_size(rpival.hash_type),
        .chunk_size = chunk_size,
        .num_chunks =
            (uint16_t)roundup(be16toh(proof_node->len_record),
                              rpival.chunk_size),
        .tree_levels = (uint16_t)logb2(rpival.num_chunks),
        .gen_orig = (unsigned char)proof_node->gen_orig
    };
    rpival.buf_length = be16toh(proof_node->len_record);
    rpival.salt_index = 0;
    rpival.chunk_index = 0;
    rpival.num_hashes = 0;
    rpival.hash_locs = NULL;
    rpival.proof_merkle_hashes = NULL;
    rpival.salt_locs = NULL;
    rpival.num_salts = 0;
    rpival.init_from_proof = 1;
    rpival.mdctx = EVP_MD_CTX_create();

    // Copy, do this to allow const values
    RECORD_PROOF_INFO *rpi =
        (RECORD_PROOF_INFO *) OPENSSL_malloc(sizeof(RECORD_PROOF_INFO));
    memcpy(rpi, &rpival, sizeof(rpival));
    rpi->salts = allocate_string_array(rpi->salt_size, rpi->num_chunks);
    if (rpi->salts == NULL)
        return NULL;

    rpi->hidden_chunks_ids = NULL;
    rpi->num_hidden_chunks = 0;
    rpi->buf = plaintext;
    return rpi;
}

static int is_equal_hidden_plaintext_node(SSL *s, size_t *node_length_ptr,
                                          uint16_t *hidden_chunks_ids,
                                          size_t num_hidden_chunks,
                                          unsigned char *node_start,
                                          size_t hash_size)
{
    uint16_t i;
    RECORD_PROOF_INFO *rpi;
    HIDDEN_PLAINTEXT_PROOF_NODE *hidden_node_ptr =
        (HIDDEN_PLAINTEXT_PROOF_NODE *) (node_start + *node_length_ptr);
    *node_length_ptr += HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;
    uint16_t num_salts = be16toh(hidden_node_ptr->num_salts);
    uint16_t num_hashes = be16toh(hidden_node_ptr->num_hashes);
    *node_length_ptr += (PROOF_SALT_LOC_SIZE + s->ext.salt_size) * num_salts;

    /*parse hashes from proof */
    PROOF_HASH_LOC *hash_locs =
        (PROOF_HASH_LOC *) (node_start + *node_length_ptr);
    *node_length_ptr += PROOF_MERKLE_LOC_SIZE * num_hashes;
    unsigned char **proof_hashes =
        (unsigned char **)OPENSSL_malloc(num_hashes * sizeof(unsigned char *));
    for (i = 0; i < num_hashes; ++i) {
        proof_hashes[i] = (unsigned char *)node_start + *node_length_ptr;
        *node_length_ptr += hash_size;
    }

    rpi =
        init_rpi_from_hidden_node(hidden_node_ptr, NULL, hash_locs,
                                  proof_hashes, NULL, SSL_get_salt_size(s),
                                  SSL_get_chunk_size(s), ssl_handshake_md(s));
    if (rpi == NULL)
        goto err;

    *node_length_ptr += (size_t)compute_compressed_record_length(rpi);

    if (compare_hidden_chunks_vectors
        (hidden_chunks_ids, num_hidden_chunks, rpi->hidden_chunks_ids,
         rpi->num_hidden_chunks)) {
        goto ret;
    } else {
        goto err;
    }

 ret:
    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 1;
 err:
    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 0;

}

/* Checks if the current record has the same hidden chunks as its corresponding proof node in s->ext.tlsn_proof. It
 * also computes the length of the proof node.
 */
static int is_equal_node(SSL *s, size_t *node_length_ptr,
                         TLSN_CLIENT_RECORDING * curr_record,
                         size_t record_index, int16_t **sens_mtrx,
                         unsigned char *node_start)
{
    PLAINTEXT_PROOF_NODE *plaintext_node_ptr;
    *node_length_ptr = PROOF_NODE_SIZE;
    size_t hash_size = (size_t)EVP_MD_meth_get_result_size(ssl_handshake_md(s));
    uint16_t num_chunks;
    uint16_t *hidden_chunks_ids = NULL;
    size_t num_hidden_chunks;
    num_chunks =
        roundup((uint64_t)curr_record->plaintext_size, SSL_get_chunk_size(s));
    num_hidden_chunks = 0;

    if (find_sensitive_chunks
        (num_chunks, sens_mtrx, record_index, &hidden_chunks_ids,
         &num_hidden_chunks) <= 0)
        goto err;

    switch (*node_start) {

    case hash_chain_node:
        *node_length_ptr += hash_size;
        /*after handle_init_hidds we should not write any other hash_chain_node */
        goto err;

    case merkle_hash_node:
        *node_length_ptr += hash_size;
        if (num_chunks == num_hidden_chunks) {
            goto ret;
        } else {
            goto err;
        }

    case plaintext_node:
        plaintext_node_ptr =
            (PLAINTEXT_PROOF_NODE *) (node_start + *node_length_ptr);
        *node_length_ptr += PLAINTEXT_PROOF_NODE_SIZE;
        *node_length_ptr += be16toh(plaintext_node_ptr->len_record);
        *node_length_ptr += s->ext.salt_size;
        if (num_hidden_chunks == 0) {
            goto ret;
        } else {
            goto err;
        }

    case hidden_plaintext_node:
        if (is_equal_hidden_plaintext_node
            (s, node_length_ptr, hidden_chunks_ids, num_hidden_chunks,
             node_start, hash_size)) {
            goto ret;
        } else {
            goto err;
        }
    }

 ret:
    OPENSSL_free(hidden_chunks_ids);
    return 1;
 err:
    OPENSSL_free(hidden_chunks_ids);
    return 0;
}

static int compute_hidden_plaintext_node_length(SSL *s, size_t *node_length_ptr,
                                                unsigned char *node_start,
                                                size_t hash_size)
{
    uint16_t i;
    RECORD_PROOF_INFO *rpi;

    HIDDEN_PLAINTEXT_PROOF_NODE *hidden_node_ptr =
        (HIDDEN_PLAINTEXT_PROOF_NODE *) (node_start + *node_length_ptr);
    *node_length_ptr += HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;
    uint16_t num_salts = be16toh(hidden_node_ptr->num_salts);
    uint16_t num_hashes = be16toh(hidden_node_ptr->num_hashes);

    *node_length_ptr += (PROOF_SALT_LOC_SIZE + s->ext.salt_size) * num_salts;

    /*parse hashes from proof */
    PROOF_HASH_LOC *hash_locs =
        (PROOF_HASH_LOC *) (node_start + *node_length_ptr);
    *node_length_ptr += PROOF_MERKLE_LOC_SIZE * num_hashes;
    unsigned char **proof_hashes =
        (unsigned char **)OPENSSL_malloc(num_hashes * sizeof(unsigned char *));
    for (i = 0; i < num_hashes; ++i) {
        proof_hashes[i] = (unsigned char *)node_start + *node_length_ptr;
        *node_length_ptr += hash_size;
    }

    rpi =
        init_rpi_from_hidden_node(hidden_node_ptr, NULL, hash_locs,
                                  proof_hashes, NULL, SSL_get_salt_size(s),
                                  SSL_get_chunk_size(s), ssl_handshake_md(s));
    if (rpi == NULL)
        goto err;

    *node_length_ptr += (size_t)compute_compressed_record_length(rpi);

    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 1;
 err:
    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 0;
}

/* computes the lenght of the node starting at node_start and saves it into node_length */
static int compute_node_length(SSL *s, size_t *node_length_ptr,
                               unsigned char *node_start, size_t hash_size)
{
    *node_length_ptr = PROOF_NODE_SIZE;
    PLAINTEXT_PROOF_NODE *plaintext_node_ptr;
    switch (*(node_start + *node_length_ptr - PROOF_NODE_SIZE)) {

    case hash_chain_node:
    case merkle_hash_node:
        *node_length_ptr += hash_size;
        break;

    case plaintext_node:
        plaintext_node_ptr =
            (PLAINTEXT_PROOF_NODE *) (node_start + *node_length_ptr);
        *node_length_ptr += PLAINTEXT_PROOF_NODE_SIZE;
        *node_length_ptr += be16toh(plaintext_node_ptr->len_record);
        *node_length_ptr += s->ext.salt_size;
        break;

    case hidden_plaintext_node:
        if (compute_hidden_plaintext_node_length
            (s, node_length_ptr, node_start, hash_size) <= 0)
            return 0;
        break;

    default:
        return 0;
    }

    return 1;
}

static int advance_offset_by_one_node(SSL *s, size_t *read_offset_ptr,
                                      size_t hash_size)
{
    size_t node_length;
    unsigned char *node_start = s->ext.tlsn_proof + *read_offset_ptr;
    if (compute_node_length(s, &node_length, node_start, hash_size) <= 0)
        return 0;
    *read_offset_ptr += node_length;
    return 1;
}

/* It appends the hash_chain node of the current record to proof_buf. If a hash_chain node is already there, it overwrites it */
static int overwrite_hashchain_node_proof_buf(PROOF_BUFFER * proof_buf_ptr,
                                              int hash_chain_node_written,
                                              size_t *num_proof_nodes_ptr,
                                              unsigned char *hash_chain,
                                              size_t hash_size)
{
    if (hash_chain_node_written) {
        /*overwrite previous proof node */
        proof_buf_ptr->buf_len -= PROOF_NODE_SIZE + hash_size;
        proof_buf_ptr->offset -= PROOF_NODE_SIZE + hash_size;
    }

    size_t proof_offset = proof_buf_ptr->offset;

    PROOF_NODE proof_node;
    proof_node.node_type = hash_chain_node;

    unsigned char *proof_str = proof_buf_ptr->buf;

    proof_buf_ptr->buf_len += PROOF_NODE_SIZE + hash_size;
    proof_str =
        (unsigned char *)OPENSSL_realloc(proof_str, proof_buf_ptr->buf_len);
    encode_nbo(proof_node.node_type, PROOF_NODE_SIZE, proof_str + proof_offset);
    proof_offset += PROOF_NODE_SIZE;
    memcpy(proof_str + proof_offset, hash_chain, hash_size);
    proof_offset += hash_size;

    if (proof_offset != proof_buf_ptr->buf_len)
        return 0;

    proof_buf_ptr->buf = proof_str;
    proof_buf_ptr->offset = proof_offset;
    return 1;
}

/* The write_hash_chain_index is the index of the first record that will be represented with a hash_chain node. Consider the
 * first record that has at least one non-sensitive chunk. The write_hash_chain_index is the index of record right before it.
 */
static int compute_write_hash_chain_index(SSL *s, int16_t **sens_mtrx,
                                          int64_t *write_hash_chain_index_ptr)
{

    int non_hidden_found = 0;
    size_t record_index;
    uint16_t num_chunks;
    size_t received;
    size_t recvd_index = 0;
    size_t sent_index = 0;
    TLSN_CLIENT_RECORDING *curr_record = NULL;
    uint16_t *hidden_chunks_ids = NULL;
    size_t num_hidden_chunks;

    for (record_index = 0; non_hidden_found == 0; record_index++) {

        received =
            (s->ext.
             tlsn_proof_ordvec[record_index / 8] >> (record_index % 8)) & 1;
        curr_record =
            received ? &(s->ext.tlsn_client_recv[recvd_index]) : &(s->ext.
                                                                   tlsn_client_sent
                                                                   [sent_index]);
        num_chunks =
            roundup((uint64_t)curr_record->plaintext_size,
                    SSL_get_chunk_size(s));
        num_hidden_chunks = 0;

        if (find_sensitive_chunks
            (num_chunks, sens_mtrx, record_index, &hidden_chunks_ids,
             &num_hidden_chunks) <= 0) {
            OPENSSL_free(hidden_chunks_ids);
            return -1;
        }

        if (num_hidden_chunks != num_chunks)
            non_hidden_found = 1;

        if (record_index == (s->ext.tlsn_proof_ordvec_len - 1)
            && non_hidden_found == 0) {
            SSLerr(SSL_F_COMPUTE_WRITE_HASH_CHAIN_INDEX,
                   SSL_R_ALL_RECORDS_ARE_HIDDEN);
            OPENSSL_free(hidden_chunks_ids);
            return -1;
        }

        if (received) {
            recvd_index++;
        } else {
            sent_index++;
        }
    }

    OPENSSL_free(hidden_chunks_ids);
    *write_hash_chain_index_ptr = record_index - 2;
    return 1;

}

/* Takes the hash from the hash_chain node and saves it into hash_chain */
static int parse_hashchain_node(SSL *s, size_t *read_offset_ptr,
                                unsigned char **hash_chain_ptr,
                                size_t hash_size)
{

    if (*(s->ext.tlsn_proof + *read_offset_ptr) != hash_chain_node)
        return -1;

    if (*hash_chain_ptr != NULL)
        return -1;

    *hash_chain_ptr = OPENSSL_malloc(hash_size);
    memcpy(*hash_chain_ptr, s->ext.tlsn_proof + *read_offset_ptr + 1,
           hash_size);

    return 1;
}

/*Handles all the records until the write_hash_chain_index (included)*/
static int handle_init_hidds(SSL *s, size_t *read_offset_ptr,
                             int64_t read_hash_chain_index,
                             PROOF_BUFFER * proof_buf_ptr, int16_t **sens_mtrx,
                             size_t *num_proof_nodes_ptr,
                             size_t *recvd_index_ptr, size_t *sent_index_ptr)
{
    int64_t write_hash_chain_index; /* find its definition in the comment to compute_write_hash_chain_index */
    int write_index_smaller;
    RECORD_PROOF_INFO *rpi = NULL;
    unsigned char *hash_chain = NULL;
    size_t hash_size = (size_t)EVP_MD_meth_get_result_size(ssl_handshake_md(s));
    int hash_chain_node_written = 0; /*if it's 1, it means that a hash chain node has already been appended to the proof */

    if (compute_write_hash_chain_index(s, sens_mtrx, &write_hash_chain_index) <=
        0)
        goto err;

    if (write_hash_chain_index == -1)
        goto ret;

    write_index_smaller = (write_hash_chain_index < read_hash_chain_index);

    size_t record_index;
    int received;
    TLSN_CLIENT_RECORDING *curr_record = NULL;

    for (record_index = 0; (int64_t)record_index <= write_hash_chain_index;
         record_index++) {

        received =
            (s->ext.
             tlsn_proof_ordvec[record_index / 8] >> (record_index % 8)) & 1;
        curr_record =
            received ? &(s->ext.tlsn_client_recv[*recvd_index_ptr]) : &(s->ext.
                                                                        tlsn_client_sent
                                                                        [*sent_index_ptr]);

        if (received) {
            (*recvd_index_ptr)++;
        } else {
            (*sent_index_ptr)++;
        }

        if (write_index_smaller
            || (int64_t)record_index >= read_hash_chain_index) {

            if ((int64_t)record_index == read_hash_chain_index) {
                if (parse_hashchain_node
                    (s, read_offset_ptr, &hash_chain, hash_size) <= 0)
                    goto err;

            } else {
                if (compute_merkle_root
                    (s, &rpi, curr_record, received, hash_size) <= 0)
                    goto err;

                hash_chain =
                    advance_hash_chain(rpi, hash_chain,
                                       curr_record->merkle_hash);
                if (hash_chain == NULL)
                    goto err;

                free_rpi(rpi);

            }

            if (overwrite_hashchain_node_proof_buf
                (proof_buf_ptr, hash_chain_node_written, num_proof_nodes_ptr,
                 hash_chain, hash_size) <= 0)
                goto err;

            if ((int64_t)record_index >= read_hash_chain_index) {
                if (advance_offset_by_one_node(s, read_offset_ptr, hash_size) <=
                    0)
                    goto err;

            }

            hash_chain_node_written = 1;
        }
    }

    if (*num_proof_nodes_ptr != 0) {
        goto err;
    } else {
        *num_proof_nodes_ptr = 1;
    }
 ret:
    OPENSSL_free(hash_chain);
    return 1;
 err:
    free_rpi(rpi);
    OPENSSL_free(hash_chain);
    return -1;
}

/* For each record, it appends its node on the proof buffer. The type of node 
 * depends on the hidden chunks of the record */
static int append_records_to_proof_buffer(SSL *s, size_t *read_offset_ptr,
                                          size_t *num_proof_nodes_ptr,
                                          PROOF_BUFFER * proof_buf_ptr,
                                          int16_t **sens_mtrx)
{
    size_t node_length;
    size_t record_index = 0;
    unsigned int received;
    size_t recvd_index = 0;
    size_t sent_index = 0;
    TLSN_CLIENT_RECORDING *curr_record = NULL;
    unsigned char *hash_chain = NULL;
    //RECORD_PROOF_INFO *rpi = NULL;
    int64_t read_hash_chain_index = s->ext.tlsn_proof_ordvec_len -
        be32toh(((PROOF_PAR *) s->ext.tlsn_proof)->num_proof_nodes);
    /*index of the hash chain record in the s->ext.tlsn_proof */
    if (read_hash_chain_index == 0
        && s->ext.tlsn_proof[*read_offset_ptr] != hash_chain_node)
        read_hash_chain_index = -1; /*No hash chain nodes */
    if (handle_init_hidds(s, read_offset_ptr, read_hash_chain_index,
                          proof_buf_ptr, sens_mtrx, num_proof_nodes_ptr,
                          &recvd_index, &sent_index) <= 0)
        goto err;

    if (s->ext.tlsn_client_recv_len == 0 && s->ext.tlsn_client_sent_len == 0)
        goto err;

    /* loop record per record */
    for (record_index = recvd_index + sent_index;
         record_index < s->ext.tlsn_proof_ordvec_len; record_index++) {

        received =
            (s->ext.
             tlsn_proof_ordvec[record_index / 8] >> (record_index % 8)) & 1;
        curr_record =
            received ? &(s->ext.tlsn_client_recv[recvd_index]) : &(s->ext.
                                                                   tlsn_client_sent
                                                                   [sent_index]);

        if (is_equal_node
            (s, &node_length, curr_record, record_index, sens_mtrx,
             s->ext.tlsn_proof + *read_offset_ptr)) {
            /* If the hidden chunks are the same, we can copy the node from s->ext.tlsn_proof */
            proof_buf_ptr->buf_len += node_length;
            proof_buf_ptr->buf =
                (unsigned char *)OPENSSL_realloc(proof_buf_ptr->buf,
                                                 proof_buf_ptr->buf_len);
            memcpy(proof_buf_ptr->buf + proof_buf_ptr->offset,
                   s->ext.tlsn_proof + *read_offset_ptr, node_length);
            proof_buf_ptr->offset += node_length;

            *num_proof_nodes_ptr += 1;

            if (proof_buf_ptr->offset != proof_buf_ptr->buf_len)
                goto err;

        } else {

            if (append_current_record_to_proof_buf
                (s, proof_buf_ptr, curr_record, received, record_index,
                 num_proof_nodes_ptr, sens_mtrx) <= 0)
                goto err;
        }
        if ((int64_t)record_index >= read_hash_chain_index) {
            *read_offset_ptr += node_length;
        }

        if (received) {
            recvd_index++;
        } else {
            sent_index++;
        }
    }

    OPENSSL_free(hash_chain);
    return 1;
 err:
    OPENSSL_free(hash_chain);
    return 0;
}

int SSL_tlsn_hide_sensitive_chunks(SSL *s, int option, int16_t **sens_mtrx,
                                   size_t row_num)
{
    if (row_num != s->ext.tlsn_proof_ordvec_len) {
        SSLerr(SSL_F_SSL_TLSN_HIDE_SENSITIVE_CHUNKS, SSL_R_WRONG_ROWS_NUMBER);
        return 0;
    }

    /* The old proof is in s->ext.tlsn_proof. The new proof will be first created on
     * proof_buf, and then substituted in s->ext.tlsn_proof.
     */
    PROOF_BUFFER proof_buf;
    proof_buf.buf = NULL;
    proof_buf.buf_len = 0;
    proof_buf.offset = 0;

    /*retrieve data from proof */
    PROOF_PAR *read_proof_par_ptr = (PROOF_PAR *) s->ext.tlsn_proof;

    if (requester_control_proof_par(s, *read_proof_par_ptr) <= 0) {
        SSLerr(SSL_F_SSL_TLSN_HIDE_SENSITIVE_CHUNKS,
               SSL_R_COULD_NOT_RETRIEVE_PROOF);
        return 0;
    }

    size_t read_cert_chain_len = be16toh(read_proof_par_ptr->cert_chain_len);
    size_t read_sig_len = be16toh(read_proof_par_ptr->sig_len);
    size_t read_offset = PROOF_PAR_SIZE + read_sig_len;

    /*copy first part of proof on proof buffer */
    proof_buf.buf_len = read_offset;
    proof_buf.buf = OPENSSL_malloc(proof_buf.buf_len);
    memcpy(proof_buf.buf, s->ext.tlsn_proof, proof_buf.buf_len);
    proof_buf.offset = proof_buf.buf_len;
    PROOF_PAR *write_proof_par_ptr = (PROOF_PAR *) proof_buf.buf;
    write_proof_par_ptr->num_proof_nodes = 0;

    /*include or omit the certificate chain */
    if (option == INCLUDE_CERT_CHAIN) {
        add_cert_chain_to_proof_buffer(s, &proof_buf);
        write_proof_par_ptr = (PROOF_PAR *) (proof_buf.buf);
    }

    if (option == OMIT_CERT_CHAIN) {
        write_proof_par_ptr->cert_chain_len = 0;
    }

    read_offset += read_cert_chain_len;
    size_t num_proof_nodes = 0;
    if (append_records_to_proof_buffer
        (s, &read_offset, &num_proof_nodes, &proof_buf, sens_mtrx) <= 0) {
        OPENSSL_free(proof_buf.buf);
        return -1;
    }

    if (read_offset != s->ext.tlsn_proof_len)
        goto err;

    write_proof_par_ptr = (PROOF_PAR *) proof_buf.buf;
    write_proof_par_ptr->num_proof_nodes = htonl((uint32_t)num_proof_nodes);
    OPENSSL_free(s->ext.tlsn_proof);
    s->ext.tlsn_proof = proof_buf.buf;
    s->ext.tlsn_proof_len = proof_buf.buf_len;
    return 1;
 err:
    OPENSSL_free(proof_buf.buf);
    return -1;
}

static int verify_proof_signature(unsigned char *signature,
                                  size_t signature_len,
                                  EVP_PKEY *generator_pubkey,
                                  PROOF_PAR * proof_par_ptr,
                                  unsigned char *final_hash)
{
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *vrfy_ctx = NULL;
    const EVP_MD *hash_type = from_hashalg_to_evpmd(proof_par_ptr->hash_type);
    unsigned int hash_size = EVP_MD_meth_get_result_size(hash_type);
    unsigned char hashed_data[hash_size];

    if ((mdctx = EVP_MD_CTX_create()) == NULL
        || 1 != EVP_DigestInit_ex(mdctx, hash_type, NULL)
        || 1 != EVP_DigestUpdate(mdctx, &(proof_par_ptr->tlsn_version),
                                 sizeof(uint8_t))
        || 1 != EVP_DigestUpdate(mdctx, final_hash, hash_size)
        || 1 != EVP_DigestUpdate(mdctx, &proof_par_ptr->start_time,
                                 sizeof(uint64_t))
        || 1 != EVP_DigestUpdate(mdctx, &proof_par_ptr->stop_time,
                                 sizeof(uint64_t))
        || 1 != EVP_DigestUpdate(mdctx, &proof_par_ptr->salt_size,
                                 sizeof(uint16_t))
        || 1 != EVP_DigestUpdate(mdctx, &proof_par_ptr->chunk_size,
                                 sizeof(uint16_t))
        || 1 != EVP_DigestUpdate(mdctx, &proof_par_ptr->hash_type,
                                 sizeof(uint8_t))
        || 1 != EVP_DigestFinal_ex(mdctx, hashed_data, &hash_size)) {
        goto err;
    }

    if ((vrfy_ctx = EVP_PKEY_CTX_new(generator_pubkey, NULL)) == NULL
        || EVP_PKEY_verify_init(vrfy_ctx) <= 0
        || EVP_PKEY_verify(vrfy_ctx, signature, signature_len, hashed_data,
                           hash_size) < 1) {
        goto err;
    }

    EVP_PKEY_CTX_free(vrfy_ctx);
    EVP_MD_CTX_destroy(mdctx);
    return 1;
 err:
    EVP_PKEY_CTX_free(vrfy_ctx);
    EVP_MD_CTX_destroy(mdctx);
    return 0;

}

/* outbuf has to be of length hash_size*/
static int compute_merkle_tree_from_proof(RECORD_PROOF_INFO * rpi,
                                          unsigned char *outbuf)
{
    rpi->chunk_index = 0;
    return compute_merkle_tree2(rpi, 0, outbuf);
}

static int32_t salt_is_in_proof(PROOF_SALT_LOC * salt_locs,
                                uint16_t num_proof_salts, int level,
                                uint16_t salt_index)
{
    int i;
    for (i = 0; i < num_proof_salts; ++i) {
        if (be16toh(salt_locs[i].tree_level) == level
            && be16toh(salt_locs[i].salt_index) == salt_index) {
            return i;
        }
    }
    return -1;
}

static int compute_salts_from_proof_salts2(RECORD_PROOF_INFO * rpi,
                                           const int level,
                                           unsigned char **proof_salts)
{

    int32_t in_proof_index;

    if (rpi->salt_index >= rpi->num_chunks) {
        return 1;
    }
    // Special case: single chunk
    if (rpi->num_chunks == 1) {
        return 0;
    }
    // If this part is in the proof
    in_proof_index =
        salt_is_in_proof(rpi->salt_locs, rpi->num_salts, level,
                         rpi->salt_index);
    if (in_proof_index != -1) {
        // Just copy it, if it is a final salt
        if (level == rpi->tree_levels) {
            memcpy(rpi->salts[rpi->salt_index], proof_salts[in_proof_index],
                   rpi->salt_size);
            if (is_hidden_chunk
                (rpi->hidden_chunks_ids, rpi->num_hidden_chunks,
                 rpi->salt_index))
                return 0;
            rpi->salt_index += 1;
            return 1;
        } else {
            // Take it from the proof and run the normal subtree execution
            return compute_salt_tree2(rpi, level, proof_salts[in_proof_index]);
        }
    }
    // Useless leaf
    if (level == rpi->tree_levels) {
        if (!is_hidden_chunk
            (rpi->hidden_chunks_ids, rpi->num_hidden_chunks, rpi->salt_index))
            return 0;
        rpi->salt_index += 1;
        return 1;
    }
    // Traverse down
    if (compute_salts_from_proof_salts2(rpi, level + 1, proof_salts) < 1)
        return 0;
    if (rpi->salt_index >= rpi->num_chunks) {
        return 1;
    }

    if (compute_salts_from_proof_salts2(rpi, level + 1, proof_salts) < 1)
        return 0;

    return 1;
}

static int compute_salts_from_proof_salts(RECORD_PROOF_INFO * rpi,
                                          unsigned char **proof_salts)
{
    rpi->salt_index = 0;
    return compute_salts_from_proof_salts2(rpi, 0, proof_salts);
}

/* Inflate the record by putting 'X' where content was censored*/
static int inflate_record(RECORD_PROOF_INFO * rpi,
                          unsigned char *compressed_buffer)
{
    uint16_t i;
    int j;
    uint16_t num_normal_chunks = 0;
    uint16_t chunk_length;
    uint16_t offset = 0;

    for (i = 0; i < rpi->num_chunks; ++i) {
        chunk_length = get_chunk_length2(rpi, i);
        if (is_hidden_chunk(rpi->hidden_chunks_ids, rpi->num_hidden_chunks, i)) {
            for (j = 0; j < chunk_length; ++j) {
                // Put this for hidden chunks
                ((unsigned char *)rpi->buf)[offset] = 'X';
                offset++;
            }
        } else {
            // Copy normal records
            memcpy((unsigned char *)rpi->buf + offset,
                   compressed_buffer + (num_normal_chunks * rpi->chunk_size),
                   chunk_length);
            offset += chunk_length;
            num_normal_chunks++;
        }
    }
    if (offset != rpi->buf_length)
        return 0;
    return 1;
}

static int advance_hash_chain_from_hidden(unsigned char **final_hash_ptr,
                                          unsigned char *proof_str,
                                          size_t *offset_ptr,
                                          uint16_t salt_size,
                                          uint16_t chunk_size,
                                          const EVP_MD *hash_type)
{
    uint16_t hash_size = EVP_MD_meth_get_result_size(hash_type);
    unsigned char *merkle_root = NULL;
    uint16_t i = 0;
    RECORD_PROOF_INFO *rpi = NULL;

    HIDDEN_PLAINTEXT_PROOF_NODE *hidden_node_ptr =
        (HIDDEN_PLAINTEXT_PROOF_NODE *) (proof_str + *offset_ptr);
    *offset_ptr += HIDDEN_PLAINTEXT_PROOF_NODE_SIZE;
    uint16_t num_salts = be16toh(hidden_node_ptr->num_salts);
    uint16_t num_hashes = be16toh(hidden_node_ptr->num_hashes);

    /*parse salts from proof */
    PROOF_SALT_LOC *salt_locs = (PROOF_SALT_LOC *) (proof_str + *offset_ptr); /* locations of salts in tree */
    *offset_ptr += PROOF_SALT_LOC_SIZE * num_salts;
    unsigned char **proof_salts =
        (unsigned char **)OPENSSL_malloc(num_salts * sizeof(unsigned char *));
    for (i = 0; i < num_salts; ++i) {
        proof_salts[i] = (unsigned char *)proof_str + *offset_ptr;
        *offset_ptr += salt_size;
    }

    /*parse hashes from proof */
    PROOF_HASH_LOC *hash_locs = (PROOF_HASH_LOC *) (proof_str + *offset_ptr); /* location of hashes in tree */
    *offset_ptr += PROOF_MERKLE_LOC_SIZE * num_hashes;
    unsigned char **proof_hashes =
        (unsigned char **)OPENSSL_malloc(num_hashes * sizeof(unsigned char *));
    for (i = 0; i < num_hashes; ++i) {
        proof_hashes[i] = (unsigned char *)proof_str + *offset_ptr;
        *offset_ptr += hash_size;
    }

    rpi =
        init_rpi_from_hidden_node(hidden_node_ptr, NULL, hash_locs,
                                  proof_hashes, salt_locs, salt_size,
                                  chunk_size, hash_type);
    if (rpi == NULL)
        return 0;

    if (inflate_record(rpi, proof_str + *offset_ptr) < 1)
        goto err;

    *offset_ptr += compute_compressed_record_length(rpi);
    if (compute_salts_from_proof_salts(rpi, proof_salts) < 1)
        goto err;

    merkle_root = (unsigned char *)OPENSSL_malloc(hash_size);
    if (compute_merkle_tree_from_proof(rpi, merkle_root) < 1)
        return 0;

    *final_hash_ptr = advance_hash_chain(rpi, *final_hash_ptr, merkle_root);
    if (*final_hash_ptr == NULL)
        return 0;

    OPENSSL_free(merkle_root);
    OPENSSL_free(proof_salts);
    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 1;
 err:
    OPENSSL_free(merkle_root);
    OPENSSL_free(proof_salts);
    OPENSSL_free(proof_hashes);
    free_rpi_initialized_from_proof(rpi);
    return 0;

}

static int advance_hash_chain_from_plaintext(unsigned char **final_hash_ptr,
                                             unsigned char *proof_str,
                                             size_t *offset_ptr,
                                             uint16_t salt_size,
                                             uint16_t chunk_size,
                                             const EVP_MD *hash_type)
{
    unsigned char *merkle_root = NULL;
    PLAINTEXT_PROOF_NODE *plaintext_node_ptr =
        (PLAINTEXT_PROOF_NODE *) (proof_str + *offset_ptr);
    *offset_ptr += PLAINTEXT_PROOF_NODE_SIZE;

    RECORD_PROOF_INFO *rpi =
        init_rpi_from_plaintext_node(plaintext_node_ptr,
                                     proof_str + *offset_ptr, salt_size,
                                     chunk_size, hash_type);
    if (rpi == NULL)
        return 0;
    *offset_ptr += rpi->buf_length;

    if (compute_salt_tree(rpi, proof_str + *offset_ptr) <= 0)
        goto err;
    *offset_ptr += rpi->salt_size;

    merkle_root = (unsigned char *)OPENSSL_malloc(rpi->hash_size);
    if (compute_merkle_tree(rpi, merkle_root) <= 0)
        goto err;

    *final_hash_ptr = advance_hash_chain(rpi, *final_hash_ptr, merkle_root);
    if (*final_hash_ptr == NULL)
        goto err;

    free_rpi(rpi);
    OPENSSL_free(merkle_root);
    return 1;

 err:
    free_rpi(rpi);
    OPENSSL_free(merkle_root);
    return 0;

}

static int advance_hash_chain_from_merkle(unsigned char *final_hash,
                                          unsigned char *merkle_root,
                                          const EVP_MD *hash_type,
                                          uint16_t hash_size_value)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int hash_size = hash_size_value;
    if (EVP_DigestInit_ex(ctx, hash_type, NULL) < 1
        || EVP_DigestUpdate(ctx, &hash_chain_marker,
                            sizeof(hash_chain_marker)) < 1
        || EVP_DigestUpdate(ctx, final_hash, hash_size) < 1
        || EVP_DigestUpdate(ctx, merkle_root, hash_size) < 1
        || EVP_DigestFinal_ex(ctx, final_hash, &hash_size) < 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    return 1;
}

static int advance_hash_chain_from_curr_node(unsigned char **final_hash_ptr,
                                             PROOF_PAR * proof_par_ptr,
                                             unsigned char *proof_str,
                                             size_t *offset_ptr,
                                             uint32_t curr_node)
{
    uint16_t salt_size = be16toh(proof_par_ptr->salt_size);
    uint16_t chunk_size = be16toh(proof_par_ptr->chunk_size);
    const EVP_MD *hash_type = from_hashalg_to_evpmd(proof_par_ptr->hash_type);
    uint16_t hash_size = EVP_MD_meth_get_result_size(hash_type);
    *offset_ptr += PROOF_NODE_SIZE;

    switch (*(proof_str + *offset_ptr - PROOF_NODE_SIZE)) {

    case hash_chain_node:
        if (curr_node != 0)
            return 0;
        if (*final_hash_ptr != NULL)
            return 0;
        *final_hash_ptr = OPENSSL_malloc(hash_size);
        memcpy(*final_hash_ptr, proof_str + *offset_ptr, hash_size);
        *offset_ptr += hash_size;
        break;

    case merkle_hash_node:
        if (curr_node == 0)
            return 0;
        if (*final_hash_ptr == NULL)
            return 0;
        if (advance_hash_chain_from_merkle
            (*final_hash_ptr, proof_str + *offset_ptr, hash_type,
             hash_size) < 1)
            return 0;
        *offset_ptr += hash_size;
        break;

    case plaintext_node:
        if (advance_hash_chain_from_plaintext
            (final_hash_ptr, proof_str, offset_ptr, salt_size, chunk_size,
             hash_type) < 1)
            return 0;
        break;

    case hidden_plaintext_node:
        if (advance_hash_chain_from_hidden
            (final_hash_ptr, proof_str, offset_ptr, salt_size, chunk_size,
             hash_type) < 1)
            return 0;
        break;

    default:
        SSLerr(SSL_F_ADVANCE_HASH_CHAIN_FROM_CURR_NODE,
               SSL_R_ERROR_PARSING_RECORDS);
        return 0;
    }

    return 1;
}

static int compute_final_hash_from_proof(unsigned char **final_hash_ptr,
                                         PROOF_PAR * proof_par_ptr,
                                         unsigned char *proof_str,
                                         size_t *offset_ptr)
{
    uint32_t curr_node;
    for (curr_node = 0; curr_node < be32toh(proof_par_ptr->num_proof_nodes);
         curr_node++) {
        if (advance_hash_chain_from_curr_node
            (final_hash_ptr, proof_par_ptr, proof_str, offset_ptr,
             curr_node) < 1)
            return 0;
    }

    return 1;
}

static int check_proof_time(PROOF_PAR * proof_par_ptr, uint64_t min_start_time,
                            uint64_t max_start_time, uint64_t min_stop_time,
                            uint64_t max_stop_time, uint64_t max_conv_duration)
{
    if (be64toh(proof_par_ptr->start_time) < min_start_time
        || be64toh(proof_par_ptr->start_time) > max_start_time
        || be64toh(proof_par_ptr->stop_time) < min_stop_time
        || be64toh(proof_par_ptr->stop_time) > max_stop_time
        || be64toh(proof_par_ptr->stop_time) -
        be64toh(proof_par_ptr->start_time) > max_conv_duration)
        return 0;

    return 1;
}

/*this function also parses the pub key of the generator*/
static int verify_cert_chain_from_proof(EVP_PKEY **generator_pubkey_ptr, SSL *s,
                                        unsigned char *cert_chain,
                                        size_t cert_chain_len)
{
    unsigned char *offset_tracker = cert_chain;
    X509 *generator_cert, *x;
    STACK_OF (X509) * sk = sk_X509_new_null();

    generator_cert =
        d2i_X509(NULL, (const unsigned char **)&offset_tracker, cert_chain_len);
    if (generator_cert == NULL) {
        SSLerr(SSL_F_VERIFY_CERT_CHAIN_FROM_PROOF, SSL_R_INVALID_CERT_CHAIN);
        goto err;
    }

    /*stores the certificate chain of the generator into sk */
    offset_tracker = cert_chain;
    while (offset_tracker - cert_chain != (int64_t)cert_chain_len) {
        x = d2i_X509(NULL, (const unsigned char **)&offset_tracker,
                     cert_chain_len - (offset_tracker - cert_chain));
        if (x == NULL
            || (offset_tracker - cert_chain) > (int64_t)cert_chain_len) {
            SSLerr(SSL_F_VERIFY_CERT_CHAIN_FROM_PROOF,
                   SSL_R_INVALID_CERT_CHAIN);
            goto err;
        }
        sk_X509_push(sk, x);
    }

    if (ssl_verify_cert_chain(s, sk) < 1) {
        SSLerr(SSL_F_VERIFY_CERT_CHAIN_FROM_PROOF,
               SSL_R_CERT_CHAIN_NOT_VERIFIED);
        goto err;
    }

    *generator_pubkey_ptr = X509_get_pubkey(generator_cert);
    X509_free(generator_cert);
    sk_X509_pop_free(sk, X509_free);
    return 1;
 err:
    X509_free(generator_cert);
    sk_X509_pop_free(sk, X509_free);
    return 0;
}

/* Fills proof_par and signature with the data from proof. It also parses the generator's public key into gen_pubkey if necessary. */
static int parse_and_check_proof(int option, void *ptr,
                                 unsigned char *proof_str, size_t *offset_ptr,
                                 PROOF_PAR ** proof_par_ptr_ptr,
                                 unsigned char **signature_ptr,
                                 size_t *signature_len_ptr,
                                 EVP_PKEY **gen_pubkey_ptr)
{
    *proof_par_ptr_ptr = (PROOF_PAR *) proof_str;
    PROOF_PAR *proof_par_ptr = *proof_par_ptr_ptr;
    *offset_ptr += PROOF_PAR_SIZE;
    uint16_t hash_size =
        EVP_MD_meth_get_result_size(from_hashalg_to_evpmd
                                    (proof_par_ptr->hash_type));

    if (hash_size > EVP_MAX_MD_SIZE
        || be16toh(proof_par_ptr->salt_size) < MINIMUM_SALT_SIZE
        || be16toh(proof_par_ptr->salt_size) > MAXIMUM_SALT_SIZE
        || be16toh(proof_par_ptr->chunk_size) < MINIMUM_CHUNK_SIZE
        || be16toh(proof_par_ptr->chunk_size) > MAXIMUM_CHUNK_SIZE
        || be64toh(proof_par_ptr->stop_time) <
        be64toh(proof_par_ptr->start_time)) {
        SSLerr(SSL_F_PARSE_AND_CHECK_PROOF, SSL_R_INVALID_PROOF);
        return 0;
    }

    *signature_ptr = proof_str + *offset_ptr;
    *signature_len_ptr = be16toh(proof_par_ptr->sig_len);
    *offset_ptr += *signature_len_ptr;

    unsigned char *cert_chain = proof_str + *offset_ptr;
    size_t cert_chain_len = be16toh(proof_par_ptr->cert_chain_len);
    *offset_ptr += cert_chain_len;

    if (option == OMIT_CERT_CHAIN && cert_chain_len == 0) {
        if (EVP_PKEY_up_ref((EVP_PKEY *)ptr) < 1)
            return 0;
        *gen_pubkey_ptr = (EVP_PKEY *)ptr;
    } else if (option == INCLUDE_CERT_CHAIN && cert_chain_len != 0) {
        /*parses the key of the generator if valid */
        if (verify_cert_chain_from_proof
            (gen_pubkey_ptr, (SSL *)ptr, cert_chain, cert_chain_len) < 1)
            return 0;
    } else {                    /*error handling */
        if (option == OMIT_CERT_CHAIN) {
            SSLerr(SSL_F_PARSE_AND_CHECK_PROOF,
                   SSL_R_FOUND_UNEXPECTED_CERTIFICATE_CHAIN);
        } else {
            SSLerr(SSL_F_PARSE_AND_CHECK_PROOF,
                   SSL_R_NO_CERTIFICATE_CHAIN_FOUND);
        }
        return 0;
    }

    return 1;
}

/* option can be either INCLUDE_CERT_CHAIN or OMIT_CERT_CHAIN. It tells
 * you if you expect a proof with a cert chain or not. ptr is an (SSL *)
 * if the option is INCLUDE_CERT_CHAIN, otherwise it is an (EVP_PKEY *).
 */
static int SSL_tlsn_verify_internal(int option, void *ptr,
                                    unsigned char *proof_str, size_t proof_size,
                                    uint64_t min_start_time,
                                    uint64_t max_start_time,
                                    uint64_t min_stop_time,
                                    uint64_t max_stop_time,
                                    uint64_t max_conv_duration)
{

    size_t offset = 0;
    PROOF_PAR *proof_par_ptr;
    unsigned char *signature;   /*it's the evidence */
    size_t signature_len;
    EVP_PKEY *generator_pubkey = NULL;
    unsigned char *final_hash = NULL;

    if (parse_and_check_proof
        (option, ptr, proof_str, &offset, &proof_par_ptr, &signature,
         &signature_len, &generator_pubkey) < 1)
        goto err;

    if (check_proof_time
        (proof_par_ptr, min_start_time, max_start_time, min_stop_time,
         max_stop_time, max_conv_duration) < 1) {
        SSLerr(SSL_F_SSL_TLSN_VERIFY_INTERNAL,
               SSL_R_CONVERSATION_OUTSIDE_TIME_CONSTRAINTS);
        goto err;
    }

    if (compute_final_hash_from_proof
        (&final_hash, proof_par_ptr, proof_str, &offset) < 1)
        goto err;

    if (offset != proof_size) {
        SSLerr(SSL_F_SSL_TLSN_VERIFY_INTERNAL, SSL_R_INVALID_PROOF_SIZE);
        goto err;
    }

    if (verify_proof_signature
        (signature, signature_len, generator_pubkey, proof_par_ptr,
         final_hash) < 1) {
        SSLerr(SSL_F_SSL_TLSN_VERIFY_INTERNAL,
               SSL_R_PROOF_DOES_NOT_MATCH_SIGNATURE);
        goto err;
    }

    OPENSSL_free(final_hash);
    EVP_PKEY_free(generator_pubkey);
    return 1;

 err:
    OPENSSL_free(final_hash);
    EVP_PKEY_free(generator_pubkey);
    return 0;
}

int SSL_tlsn_verify_with_certchain(SSL *s, unsigned char *proof_str,
                                   size_t proof_size, uint64_t min_start_time,
                                   uint64_t max_start_time,
                                   uint64_t min_stop_time,
                                   uint64_t max_stop_time,
                                   uint64_t max_conv_duration)
{
    return SSL_tlsn_verify_internal(INCLUDE_CERT_CHAIN, s, proof_str,
                                    proof_size, min_start_time, max_start_time,
                                    min_stop_time, max_stop_time,
                                    max_conv_duration);

}

int SSL_tlsn_verify_no_certchain(EVP_PKEY *generator_pubkey,
                                 unsigned char *proof_str, size_t proof_size,
                                 uint64_t min_start_time,
                                 uint64_t max_start_time,
                                 uint64_t min_stop_time, uint64_t max_stop_time,
                                 uint64_t max_conv_duration)
{
    return SSL_tlsn_verify_internal(OMIT_CERT_CHAIN, generator_pubkey,
                                    proof_str, proof_size, min_start_time,
                                    max_start_time, min_stop_time,
                                    max_stop_time, max_conv_duration);

}

int SSL_tls_get_proof_string(SSL *s, unsigned char **proof_str_ptr,
                             uint64_t *proof_size_ptr)
{
    *proof_str_ptr = s->ext.tlsn_proof;
    *proof_size_ptr = s->ext.tlsn_proof_len;

    if (*proof_str_ptr == NULL || *proof_size_ptr == 0) {
        SSLerr(SSL_F_SSL_TLS_GET_PROOF_STRING, SSL_R_COULD_NOT_RETRIEVE_PROOF);
        return 0;
    } else {
        return 1;
    }

}
