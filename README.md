# TLS-N IMPLEMENTATION FOR OPENSSL

This repository contains the implementation of TLS-N for OpenSSL written by me (Fabio De Rubeis). [TLS-N](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/system-security-group-dam/research/publications/pub2018/ndss2018ritzdorf.pdf) is a protocol for the non-repudiation of TLS sessions developed at ETH Zurich. The description of TLS-N can also be found in the unpublished internet-draft [tlsn.txt](https://github.com/FDeRubeis/tls-n/blob/master/tlsn.txt) written by me with the help of H. Ritzdorf and K. Wüst. The code in this repository has been forked from the [OpenSSL repository](https://github.com/openssl/openssl).

TLS-N library:  
[./ssl/tls13_tlsn.c](https://github.com/FDeRubeis/tls-n/blob/master/ssl/tls13_tlsn.c)  
TLS-N tests:  
[./test/tls13tlsntest.c](https://github.com/FDeRubeis/tls-n/blob/master/test/tls13tlsntest.c)  
[./test/recipes/90-test_tls13tlsn.t](https://github.com/FDeRubeis/tls-n/blob/master/test/recipes/90-test_tls13tlsn.t)  
TLS-N user-available functions documentation:  
[./doc/man3/SSL_CTX_set_tlsn_extension_client.pod](https://github.com/FDeRubeis/tls-n/blob/master/doc/man3/SSL_CTX_set_tlsn_extension_client.pod)  
TLS-N internet-draft:  
[./tlsn.txt](https://github.com/FDeRubeis/tls-n/blob/master/tlsn.txt)

## Core functions

The most important functions from the TLS-N library are the following:
* *SSL_add_record_to_evidence* - this function is called during the reading and writing routine of a record. On Server side, it computes the trees and advances the hash chain by one step. On client side, it stores the record.
* *tlsn_handle_message* - this function is called during the reading routine, when a TLS-N message is received. It parses the message.
* *tlsn_send_ord_vector* - this function sends the ordering vector.

All the functions are implemented in [ssl/tls13_tlsn.c](https://github.com/FDeRubeis/tls-n/blob/master/ssl/tls13_tlsn.c) 


## Implementation details

The implementation follows the specifications from the original [TLS-N paper](https://ethz.ch/content/dam/ethz/special-interest/infk/inst-infsec/system-security-group-dam/research/publications/pub2018/ndss2018ritzdorf.pdf).

In order to support long sessions, an additional feature was implemented that sends the partial ordering vector after its length limit has been reached (8192 messages). After the 8192th message, the server automatically sends the partial ordering vector to the client. The client will automatically read and store all the partal ordering vectors and will use them at the end of the session to build the proof.

