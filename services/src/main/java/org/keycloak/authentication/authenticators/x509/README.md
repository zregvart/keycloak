# Mutual SSL User Authentication

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

The implementation supports Browser and Direct Grant Flows.
 - Browser Flow corresponds to OAuth 2.0 Implicit Flow
 - Direct Grant Flow corresponds to OAuth 2.0 Resource Owner Password Credential Flow

## Features

 - The following are the supported certificate identity extraction strategies:
   - Match SubjectDN using regular expression
   - X500 Subject's e-mail attribute
   - X500 Subject's Common Name attribute
   - Match IssuerDN using regular expression
   - X500 Issuer's e-mail attribute
   - X500 Issuer's Common Name attribute
   - Certificate Serial Number
 - User Identity/User mappings:
    - User identity to Username or E-mail
    - User identity to User Custom Attribute
 - Revocation status checking using CLR
 - Revocation status checking using CRL/Distribution Point
 - Revocation status checking using OCSP/Responder URI
 - Certificate KeyUsage validation
 - Certificate ExtendedKeyUsage validation


## Configure WildFly to enable mutual SSL

- The first step is configure WildFly to enable mutual SSL authentication.
The instructions how to it can be found in WildFly 9 documentation:
https://docs.jboss.org/author/display/WFLY9/Admin+Guide#AdminGuide-EnableSSL.

```
<security-realms>
    <security-realm name="ssl-realm">
        <server-identities>
             <ssl>
                 <keystore path="[server].jks" relative-to="jboss.server.config.dir" keystore-password="[store password]"/>
             </ssl>
        </server-identities>
        <authentication>
             <truststore path="[trusted store].jks" relative-to="jboss.server.config.dir" keystore-password="[password]"/>
        </authentication>
    </security-realm>
</security-realms>
```

Where
  - [server].jks contains an X509 private key used for both inbound and outbound SSL connections
  - [trusted store].jks is a trust store used to verify the certificates of the remote side of the connection,
  i.e. the client certificates. Ordinarily, the store contains X509 issuing authority certificates
  that were used to sign the client certificates.

- Next is to enable Https listener to allow secure access to the server.
See https://docs.jboss.org/author/display/WFLY9/Admin+Guide#AdminGuide-HTTPSlistener for
instructions how to configure WildFly to enable Https.

```
<subsystem xmlns="urn:jboss:domain:undertow:3.0">
    <buffer-cache name="default"/>
    <server name="default-server">
        <https-listener name="default" socket-binding="https" security-realm="ssl-realm" verify-client="requested"/>
    </server>
</subsystem>
```

Make sure that the "security-realm" option is set to whatever security realm which defines
the SSL security context you've configured earlier.

Another important option is "verify-client". Set it to "REQUESTED" to have the server
optionally ask for a client certificate during SSL handshake.

- Install any local client certificates so that the browser can find
  them when negotiating the SSL connection.

## Authenticating users using X509 client certificate

- A client sends an authentication request over SSL/TLS channel
- During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
  used to encrypt the data used to establish a secret key.
- The container (wildfly) validates the certificate PKIX path
- The authenticator validates the client certificate as follows:
  - Check the certificate revocation status using CRL and/or CRL Distribution Points
  - Check the Certificate revocation status using OCSP
  - Validate certificate's key usage
  - Validate certificate's extended key usage
- The server extracts the user identity and maps to to an existing user
- Once the certificate is mapped to an existing user, the behavior diverges depending on the Flow:
  - In the Browser flow, the server prompts the user to confirm whether to continue with the found identity or to ignore it
     and instead sign in using the Username/password Login Form
  - In the Direct Grant Flow, the server signs in the user

### User Identity Extraction

There are several ways to extract a user identity from a X509 certificate. Most common
strategy is to use the Common Name or E-mail attribute from either Subject
or Issuer DN.
User identity can also be extracted by applying a regular expression to
Subject Distinguished Name or Issuer Distinguished Name. For example, the
regular expression below will match the e-mail field of subject's DN:
```
emailAddress=(.*?)(?:,|$)
```

### Mapping user identity to existing user

The user identity mapping can be configured to map the extracted user identity
to a username or e-mail or to a user with a custom attribute which value matches
the extracted user identity.


### X509 Certificate Authentication using Browser Flow

* Using keycloak admin console, click on "Authentication" and select "Browser" flow
* Make a copy of "Browser" flow and enter "x509 Browser" to be the name of the new flow
* Click on add execution .. and add "X509/Validate Username Form"
* Using up/down buttons, move the newly added execution above "x509 Forms" Auth Type entry
* Configure the x509 authentication by clicking on "Actions/Config"

### X509 Certificate Authentication using Direct Grant Flow

* Using keycloak admin console, click on "Authentication" and select "Direct Grant" flow
* Make a copy of "Direct Grant" flow and enter "x509 Direct Grant" to be the name of the new flow
* Delete "Validate Username" and "Password" authenticators
* Click on "Execution" and add "X509/Validate Username" and sets the type to "REQUIRED"

To verify Direct Grant, run the following command:

```
$ curl https://[host][:port]/auth/realms/master/protocol/openid-connect/token --insecure
       --data "grant_type=password&scope=openid profile&username=&password="
       --user [client_id]:[client_secret]
       -E /path/to/[client_cert].crt
       --key /path/to/[client_cert].key
```

* [host][:port] is the address of the remote keycloak server instance
* [client_id]  is OIDC client id, i.e. "oauth2.client"
* [client_secret] is OIDC client secret, i.e. "aa0f9e94-745c-4f41-9160-1507c3f11153"
* [client_cert].crt is a public client certificate in PEM format
* [client_cert].key is private key in PEM format

## Running the X509 integration tests
X509 requires SSL/TSL protocol, so by default X509 integration tests are excluded. To verify X509 authentication functionality, you will need to run the integration test suite with TLS/SSL enabled.
```
$ mvn clean install -f testsuite/integration-arquillian/pom.xml -Pauth-server-wildfly -Dauth.server.ssl.required -Dtest=*X509*
```
### Debugging x509 integration tests: TLS/SSL diagnostics 
To enable SSL/TLS diagnostics when running X509 authentication tests, enable the built-in debug facility activated by defining javax.net.debug System property:
```
mvn clean install -f testsuite/integration-arquillian/pom.xml -Pauth-server-wildfly -Dauth.server.ssl.required -Dtest=*X509* -Djavax.net.debug=ssl:handshake
```

## Running X509 integration tests against an OCSP server
X509 authentication allows certificate revocation status checking using an OCSP server.
To run the OCSP integration tests, you will need to manually start an OCSP server.
Below is an example how to run the OCSP integration tests using the openssl tool
and a simple OCSP server.

- Open a terminal window and change the current directory to
```
testsuite/integration-arquillian/servers/auth-server/jboss/common/keystore/
```
- Start a simple OCSP server using 'openssl ocsp' command:
```
openssl ocsp -port 127.0.0.1:8888 -text -sha256 \
    -index ocsp/index.txt \
    -CA ocsp/certs/ca-chain.crt \
    -rkey ocsp/private/intermediate-ca.key \
    -rsigner ocsp/certs/intermediate-ca.crt -nrequest 2
```
- Open another terminal, change the current directory to the directory above, and send an OCSP request to the OCSP server:
```
openssl ocsp -CAfile ocsp/certs/ca-chain.crt \
    -url http://127.0.0.1:8888 -resp_text \
    -issuer ocsp/certs/intermediate-ca.crt \
    -cert client.crt
```
- The output should like the following:
```
OCSP Response Data:
    OCSP Response Status: successful (0x0)
    Response Type: Basic OCSP Response
    Version: 1 (0x0)
    Responder Id: C = US, ST = MA, L = Boston, O = Red Hat, OU = Keycloak, CN = Keycloak
...
```
- Run the OCSP x509 integration tests as follows:
```
mvn clean install -f testsuite/integration-arquillian/pom.xml -Pauth-server-wildfly -Dauth.server.ssl.required -Dtest=*OCSPResponderTest*
```

