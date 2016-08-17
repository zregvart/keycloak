=================================================
Mutual SSL User Authentication
=================================================

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

The implementation supports Browser and Direct Grant Flows.
 - Browser Flow corresponds to OAuth 2.0 Implicit Flow
 - Direct Grant Flow corresponds to OAuth 2.0 Resource Owner Password Credential Flow

----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
Steps to authenticate users using X509 client certificate
----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
- A client sends an authentication request over SSL/TLS channel
- During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
  used to encrypt the data used to establish a secret key .
- The server validates the certificate according to certificate validation algorithm:
  - Validate the certificate dates
  - Validate the certificate trust path
  - Check the certificate revocation status using CRL and/or CRL Distribution Points
  - Check the Certificate revocation status using OCSP
- The server extracts the user identity using one of the configured user identity extractors.
  Supported user identity extractors are:
  - User identity is extracted from Certificate's Subject DN field using a regular expression specified by the user
  - User identity is extracted from Certificate's Issuer DN field using a regular expression specified by the user
  - User identity is the Certificate's Serial Number
- The server maps the extracted user identity to an existing user using one of the
  available user identity mappers
  Supported user identity mappers:
  - User identity is the Username or email
  - User identity is a value of a custom attribute
- Once the certificate is mapped to an existing user, the behavior diverges depending on the Flow:
  - In the Browser flow, the server prompts the user to confirm whether to continue with the found identity or to ignore it
     and instead sign in using the Username/password Login Form
  - In the Direct Grant Flow, the server signs in the user


----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
Configure Browser Flow to enable X509 Certificate Authentication
----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
To configure Browser flow to support X509 client certificate authentication:
* Make a copy of "Browser" flow and give it a name "x509 Browser"
* Click on add execution .. and add "X509/Validate Username Form"
* Using up/down buttons, move the newly added execution above "x509 Forms" Auth Type entry
* Configure the x509 authentication by clicking on "Actions/Config"

----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
Configure Direct Grant Flow to enable X509 Certificate Authentication
----~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~--------------------------
To configure Direct Grant Flow to use mutual SSL and X509 client certificate:
* Make a copy of "Direct Grant" flow and give it a name "Direct Grant using mutual SSL"
* Delete "Validate Username" and "Password" authenticators
* Click on "Execution" and add "X509/Validate Username" and sets the type to "REQUIRED"
* Optionally, you can validate that the certificate thumbprint matches the thumbprint of a
  certificate associated with user. Click on "Execution", add "X509 Validate Thumbprint"
  and set its type to "REQUIRED".

* Note: the details how to bind certificate thumbprint to a particular user are not covered here.

To verify Direct Grant, run the following command:

$ curl https://[host][:port]/auth/realms/master/protocol/openid-connect/token --insecure \
       --data "grant_type=password&scope=openid profile&username=&password=" \
       --user [client_id]:[client_secret] \
       -E /path/to/[client_cert].pem \
       --key /path/to/[client_cert].key

Where
* [host][:port] is the keycloak server host address
* [client_id]  is OAuth2 client id, i.e. "oauth2.client"
* [client_secret] is the OAuth2 client secret, i.e. "aa0f9e94-745c-4f41-9160-1507c3f11153"
* [client_cert].pem is the client certificate public key in PEM format
* [client_cert].key is the client certificate private key in PEM format

----
Running the tests
----

The following command executes X509 authentication related tests:
 
$ mvn test -f testsuite/integration-arquillian/tests/base/pom.xml -Dtest=*X509Cert*

