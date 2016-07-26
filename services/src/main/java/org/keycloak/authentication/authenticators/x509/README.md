Mutual SSL User Authentication
=================================================

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

A common workflow is as follows:

  * A client sends an authentication request over SSL/TLS channel
  * During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
    used to encrypt the data used to establish a secret key .
  * The server verifies the client's public key certificate and uses it to authenticate the client
     *