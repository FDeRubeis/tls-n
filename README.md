# TLS-N IMPLEMENTATION FOR OPENSSL

Please find the user-available functions documented at *doc/man3/SSL_CTX_set_tlsn_extension_client.pod*

There are some important functions that are also worth to be mentioned here:
* *SSL_add_record_to_evidence* - it is called during the reading and writing routine of a record. On Server side, it computes the trees and advances the hash chain by one step. On client side, it stores the record.
* *tlsn_handle_message* - It is called during the reading routine, when a TLS-N message is received. It parses the message.
* *tlsn_send_ord_vector* - it sends the ordering vector.

All the functions are implemented in *ssl/tls13_tlsn.c*

## TESTS

Please find the source of the test in *test/tls13tlsntest.c*. It can be called running the following command in the *test* folder. 
*./test/tls13tlsntest  ./apps/tlsn_cert.pem ./apps/tlsn_key.pem ./apps/tlsn_cert.pem*

## READING AND WRITING ROUTINE

After the handshake, the two peers start exchanging messages. After the 8192th message, the server sends its ordering vector to the client. If the server is reading the 8192th message, it sends the ordering vector during the *SSL_add_record_to_evidence* function, otherwise it does it during the *ssl3_write_bytes* function.

The ordering vector message is read automatically by the client at its next *SSL_read*. Suppose, for example, that the server sends an ordering vector message and then an application data message, which we call h. The client will call a *SSL_read* to read h. The *SSL_read* will first read the ordering vector message, parse it, then call a readin routine again to read the message h. In this way, the user is required no action to read the ordering vector message. The user is unaware of the reading of the ordering vector message, since he or she only observes the reading of message h. The *SSL_tlsn_receive_response* calls an *SSL_read* sto read the tlsn-response of the server. During this *SSL_read*, all the unread ordering vector messages are read, ensuring that the client has all the necessary information before building the proof.

The tlsn-request is also read that way by the server. It means that the server peforms no active action to read the tlsn-request. It is enough for it to call *SSL_read* for any other reason. If the server only needs to read a request, but it needs to read no application data message, it can call *SSL_read* anyway. The *SSL_read* will automatically read the tlsn-request, but it will return -1, because there is no application data message to read.

