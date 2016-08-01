=================================================
Mutual SSL User Authentication
=================================================

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

A common workflow is as follows:
- A client sends an authentication request over SSL/TLS channel
- During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
  used to encrypt the data used to establish a secret key .
- The server verifies the client's public key certificate and uses it to authenticate the client:
  - certificate from/to dates
  - PKIX certificate path chain
  - TBD (the rest is not yet implemented)

The implementation supports Browser and Direct Grant flows.
 - Browser Flow is the Implicit Flow in OAuth 2.0 terminology
 - Direct Grant is the Resource Owner Password Credential Flow in OAuth 2.0 terminology.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Browser/Resource Owner Credentials Flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To configure Browser flow to support X509 client certificate authentication:
- Make a copy of "Browser" flow and give it a name "x509 Browser"
- Click on add execution .. and add "X509/Validate Username Form"
- Using up/down buttons, move the newly added execution above "x509 Forms" Auth Type entry
- Configure the x509 authentication by clicking on "Actions/Config"

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Direct Grant Flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To configure Direct Grant Flow to use mutual SSL and X509 client certificate:
- Make a copy of "Direct Grant" flow and give it a name "Direct Grant using mutual SSL"
- Delete "Validate Username" and "Password" authenticators
- Click on "Execution" and add "X509/Validate Username" and sets the type to "REQUIRED"
- To validate the certificate thumbprint matches the thumbprint of a certificate
  associated with user, click on "Execution" and add "X509 Validate Thumbprint" and set its type to "REQUIRED".

Note that the details how to bind certificate thumbprint to a particular user will be added later on.

To verify Direct Grant, run the following command:

$ curl https://online.stk.com:8443/auth/realms/master/protocol/openid-connect/token --insecure \
       --data "grant_type=password&scope=openid profile&username=&password=" \
       --user keycloak-client:aa0f9e94-745c-4f41-9160-1507c3f11153 \
       -E /C/keycloak/standalone/configuration/clientcerts/<PersonalCertPeterNalyvayko>.pem \
       --key /C/keycloak/standalone/configuration/clientcerts/<PersonalCertPeterNalyvayko>.key

