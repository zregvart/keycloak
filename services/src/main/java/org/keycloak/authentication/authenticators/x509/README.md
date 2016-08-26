=================================================
Mutual SSL User Authentication
=================================================

The authentication mechanism by which the user is authenticated using
the client's public key certificate.

Mutual SSL authentication is sometimes referred to as x509 Client Certificate Authentication.

The implementation supports Browser and Direct Grant Flows.
 - Browser Flow corresponds to OAuth 2.0 Implicit Flow
 - Direct Grant Flow corresponds to OAuth 2.0 Resource Owner Password Credential Flow

---
Configure WildFly to enable mutual SSL
---

- The first step is configure WildFly to enable mutual SSL authentication.
The instructions how to it can be found in WildFly 9 documentation:
https://docs.jboss.org/author/display/WFLY9/Admin+Guide#AdminGuide-EnableSSL.

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

Where
  - [server].jks contains an X509 private key used for both inbound and outbound SSL connections
  - [trusted store].jks is a trust store used to verify the certificates of the remote side of the connection,
  i.e. the client certificates. Ordinarily, the store contains X509 issuing authority certificates
  that were used to sign the client certificates.

- Next is to enable Https listener to allow secure access to the server.
See https://docs.jboss.org/author/display/WFLY9/Admin+Guide#AdminGuide-HTTPSlistener for
instructions how to configure WildFly to enable Https.

<subsystem xmlns="urn:jboss:domain:undertow:3.0">
    <buffer-cache name="default"/>
    <server name="default-server">
        <https-listener name="default" socket-binding="https" security-realm="ssl-realm" verify-client="requested"/>
    </server>
</subsystem>

Make sure that the "security-realm" option is set to whatever security realm which defines
the SSL security context you've configured earlier.

Another important option is "verify-client". Set it to "REQUESTED" to have the server
optionally ask for a client certificate during SSL handshake.

- Install any local client certificates so that the browser can find
  them when negotiating the SSL connection.

----
Authenticating users using X509 client certificate
----
- A client sends an authentication request over SSL/TLS channel
- During SSL/TLS handshake, the server and the client exchange their SSL/x.509/v3 digital certificates
  used to encrypt the data used to establish a secret key .
- The server validates the certificate according to certificate validation algorithm:
  - Validate the certificate dates
  - Validate the certificate trust path
  - Check the certificate revocation status using CRL and/or CRL Distribution Points
  - Check the Certificate revocation status using OCSP
  - Validate certificate's key usage
  - Validate certificate's extended key usage
- The server extracts the user identity and maps to to an existing user
- Once the certificate is mapped to an existing user, the behavior diverges depending on the Flow:
  - In the Browser flow, the server prompts the user to confirm whether to continue with the found identity or to ignore it
     and instead sign in using the Username/password Login Form
  - In the Direct Grant Flow, the server signs in the user

---
User Identity Extraction
---
There are several ways to extract a user identity from a X509 certificate. Most common
strategy is to use a regular expression to extract a username or an e-mail from the
certificate subject's name.
Another strategy is to user the issuer's name to extract the user identity. This can
be useful to map multiple certificates to a single user in keycloak.
Lastly, the certificate's serial number can be used a the user identity.

---
Mapping user identity to existing user
---
The user identity mapping can be configured to map the extracted user identity
to a username or e-mail or to a user with a custom attribute which value matches
the extracted user identity.

----
X509 Certificate Authentication using Browser Flow
----
* Using keycloak admin console, click on "Authentication" and select "Browser" flow
* Make a copy of "Browser" flow and enter "x509 Browser" to be the name of the new flow
* Click on add execution .. and add "X509/Validate Username Form"
* Using up/down buttons, move the newly added execution above "x509 Forms" Auth Type entry
* Configure the x509 authentication by clicking on "Actions/Config"

----
X509 Certificate Authentication using Direct Grant Flow
----
* Using keycloak admin console, click on "Authentication" and select "Direct Grant" flow
* Make a copy of "Direct Grant" flow and enter "x509 Direct Grant" to be the name of the new flow
* Delete "Validate Username" and "Password" authenticators
* Click on "Execution" and add "X509/Validate Username" and sets the type to "REQUIRED"
* Optionally, you can validate that the certificate thumbprint matches the thumbprint of a
  certificate associated with user. Click on "Execution", add "X509 Validate Thumbprint"
  and set its type to "REQUIRED".

* Note: the details how to bind certificate thumbprint to a particular user are not covered here.

To verify Direct Grant, run the following command:

$ curl https://[host][:port]/auth/realms/master/protocol/openid-connect/token --insecure
       --data "grant_type=password&scope=openid profile&username=&password="
       --user [client_id]:[client_secret]
       -E /path/to/[client_cert].crt
       --key /path/to/[client_cert].key

* [host][:port] is the address of the remote keycloak server instance
* [client_id]  is OIDC client id, i.e. "oauth2.client"
* [client_secret] is OIDC client secret, i.e. "aa0f9e94-745c-4f41-9160-1507c3f11153"
* [client_cert].crt is a public client certificate in PEM format
* [client_cert].key is private key in PEM format

----
Running the tests
----

TBD
 
$ mvn test -f testsuite/integration-arquillian/tests/base/pom.xml -Dtest=\*X509Cert\*

