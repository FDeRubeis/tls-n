/*
 * Generated by util/mkerr.pl DO NOT EDIT
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_DHERR_H
# define HEADER_DHERR_H

# ifdef  __cplusplus
extern "C" {
# endif
int ERR_load_DH_strings(void);
# ifdef  __cplusplus
}
# endif

/*
 * DH function codes.
 */
# define DH_F_COMPUTE_KEY                                 102
# define DH_F_DHPARAMS_PRINT_FP                           101
# define DH_F_DH_BUILTIN_GENPARAMS                        106
# define DH_F_DH_CHECK_EX                                 121
# define DH_F_DH_CHECK_PARAMS_EX                          122
# define DH_F_DH_CHECK_PUB_KEY_EX                         123
# define DH_F_DH_CMS_DECRYPT                              114
# define DH_F_DH_CMS_SET_PEERKEY                          115
# define DH_F_DH_CMS_SET_SHARED_INFO                      116
# define DH_F_DH_METH_DUP                                 117
# define DH_F_DH_METH_NEW                                 118
# define DH_F_DH_METH_SET1_NAME                           119
# define DH_F_DH_NEW_BY_NID                               104
# define DH_F_DH_NEW_METHOD                               105
# define DH_F_DH_PARAM_DECODE                             107
# define DH_F_DH_PKEY_PUBLIC_CHECK                        124
# define DH_F_DH_PRIV_DECODE                              110
# define DH_F_DH_PRIV_ENCODE                              111
# define DH_F_DH_PUB_DECODE                               108
# define DH_F_DH_PUB_ENCODE                               109
# define DH_F_DO_DH_PRINT                                 100
# define DH_F_GENERATE_KEY                                103
# define DH_F_PKEY_DH_CTRL_STR                            120
# define DH_F_PKEY_DH_DERIVE                              112
# define DH_F_PKEY_DH_KEYGEN                              113

/*
 * DH reason codes.
 */
# define DH_R_BAD_GENERATOR                               101
# define DH_R_BN_DECODE_ERROR                             109
# define DH_R_BN_ERROR                                    106
# define DH_R_CHECK_INVALID_J_VALUE                       115
# define DH_R_CHECK_INVALID_Q_VALUE                       116
# define DH_R_CHECK_PUBKEY_INVALID                        122
# define DH_R_CHECK_PUBKEY_TOO_LARGE                      123
# define DH_R_CHECK_PUBKEY_TOO_SMALL                      124
# define DH_R_CHECK_P_NOT_PRIME                           117
# define DH_R_CHECK_P_NOT_SAFE_PRIME                      118
# define DH_R_CHECK_Q_NOT_PRIME                           119
# define DH_R_DECODE_ERROR                                104
# define DH_R_INVALID_PARAMETER_NAME                      110
# define DH_R_INVALID_PARAMETER_NID                       114
# define DH_R_INVALID_PUBKEY                              102
# define DH_R_KDF_PARAMETER_ERROR                         112
# define DH_R_KEYS_NOT_SET                                108
# define DH_R_MISSING_PUBKEY                              125
# define DH_R_MODULUS_TOO_LARGE                           103
# define DH_R_NOT_SUITABLE_GENERATOR                      120
# define DH_R_NO_PARAMETERS_SET                           107
# define DH_R_NO_PRIVATE_VALUE                            100
# define DH_R_PARAMETER_ENCODING_ERROR                    105
# define DH_R_PEER_KEY_ERROR                              111
# define DH_R_SHARED_INFO_ERROR                           113
# define DH_R_UNABLE_TO_CHECK_GENERATOR                   121

#endif
