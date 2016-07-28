Mutual SSL User Authentication
=================================================

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

A common workflow is as follows:

  * A client sends an authentication request over SSL/TLS channel
  * During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
    used to encrypt the data used to establish a secret key .
  * The server verifies the client's public key certificate and uses it to authenticate the client:
    * certificate from/to dates
    * PKIX certificate path chain
    * the rest is not yet implemented

Direct grant using X509 client certificate
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
* Make a copy of "Direct Grant" flow and give it a name "Direct Grant using mutual SSL"
* Add X509 Client Certificate Authentication Authenticator
* Move x509 Authenticator to the top
* Delete "Username Validation" auth type
* Disable "Password" auth type

$ curl https://online.stk.com:8443/auth/realms/master/protocol/openid-connect/token --insecure \
       --data "grant_type=password&scope=openid profile&username=&password=" \
       --user keycloak-client:aa0f9e94-745c-4f41-9160-1507c3f11153 \
       -E /C/keycloak/standalone/configuration/clientcerts/PersonalCertPeterNalyvayko.pem \
       --key /C/keycloak/standalone/configuration/clientcerts/PersonalCertPeterNalyvayko.key

