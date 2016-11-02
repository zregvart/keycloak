/*
 * Copyright 2016 Analytical Graphics, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.keycloak.test.authentication.authenticators.x509;

import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.*;
import org.keycloak.authentication.authenticators.x509.CertificateValidator;
import org.mockserver.client.server.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.spi.InitialContextFactory;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/16/2016
 */

public class CertificateValidatorTest extends AbstractX509Test {

    private X509CRL _crl;

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this, mockServerPort);

    private MockServerClient mockServerClient;

    /**
     * See <a href="https://theholyjava.wordpress.com/2010/05/05/mocking-out-ldapjndi-in-unit-tests">Mocking LDAP in junit tests</a>
     */
    public static class MockInitialDirContextFactory implements InitialContextFactory {

        private static DirContext mockContext = null;

        public static DirContext getMockContext() {
            synchronized (MockInitialDirContextFactory.class) {
                if (mockContext == null) {
                    mockContext = (DirContext) mock(DirContext.class);
                }
            }
            return mockContext;
        }
        /**
         * Creates an initial context for beginning name resolution.
         * @param environment
         * @return
         * @throws NamingException
         */
        @Override
        public Context getInitialContext(Hashtable<?, ?> environment) throws NamingException {
            return getMockContext();
        }
    }

    @Before
    public void before() {
        try {
            _crl = generateCRL();
        } catch (GeneralSecurityException | OperatorCreationException e) {
            e.printStackTrace();
            throw new RuntimeException(e.toString());
        }
    }

    @Test
    public void testNoKeyUsageBitsSuccess() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testKeyUsageCrlSignBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enablecRLSignBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testDigitalSignatureBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableDigitalSignatureBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testKeyCertSignBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableKeyCertSign().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testAllBitsMatchValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage()
                .enablecRLSignBit()
                .enableDigitalSignatureBit()
                .enableKeyCertSign()
                .back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnMissingNoKeyUsageExtension() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableDataEncriphermentBit().back().build(clientCertificatesNoKeyUsage);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnKeyUsageDataEncriphermentBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableDataEncriphermentBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnKeyUsageDecipherOnlyBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableDecipherOnlyBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testNoExceptionOnNonCriticalKeyUsage() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableDecipherOnlyBit().back().build(clientCertificatesNonCriticalKeyUsage);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnEnciphermentBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableEnciphermentOnlyBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnKeyAgreementBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableKeyAgreementBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnKeyEnciphermentBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableKeyEnciphermentBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnNonRepudiationBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage().enableNonRepudiationBit().back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnCRLSignedDigitalSigAndNonRepudiationBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage()
                    .enablecRLSignBit()
                    .enableDigitalSignatureBit()
                    .enableNonRepudiationBit()
                .back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnCRLKeyEnciphermentAndNonRepudiationBitValidation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .keyUsage()
                .enablecRLSignBit()
                .enableKeyEnciphermentBit()
                .enableNonRepudiationBit()
                .back().build(clientCertificates);
        validator.validateKeyUsage();
    }

    @Test
    public void testNoExtendedKeyUsagesBitSuccess() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test
    public void testEmailProtectionPurposeBit() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("1.3.6.1.5.5.7.3.4").build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test
    public void testServerAuthenticatorPurposeBit() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("1.3.6.1.5.5.7.3.1").build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnClientAuthenticatorPurposeBit() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("1.3.6.1.5.5.7.3.2").build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test
    public void testNoExceptionOnNonCriticalExtendedKeyUsage() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("1.3.6.1.5.5.7.3.2").build(clientCertificatesNonCriticalKeyUsage);
        validator.validateExtendedKeyUsage();
    }

    @Test
    public void testNoExceptionOnNullInput() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse(null).build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test
    public void testNoExceptionOnEmptyInput() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("").build(clientCertificates);
        validator.validateExtendedKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnExtendedKeyUsageMissing() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .extendedKeyUsage().parse("1.3.6.1.5.5.7.3.2").build(clientCertificatesNoKeyUsage);
        validator.validateExtendedKeyUsage();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnNullCrlPath() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(false)
                    .cRLrelativePath(null)
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                .build(clientCertificates);
        validator.checkRevocationStatus();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnEmptyCrlPath() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .revocation()
                .cRLEnabled(true)
                .cRLDPEnabled(false)
                .cRLrelativePath("")
                .oCSPEnabled(false)
                .oCSPResponderURI("")
                .build(clientCertificates);
        validator.checkRevocationStatus();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testExceptionOnBadCrlPath() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .revocation()
                .cRLEnabled(true)
                .cRLDPEnabled(false)
                .cRLrelativePath("some bad path")
                .oCSPEnabled(false)
                .oCSPResponderURI("")
                .build(clientCertificates);
        validator.checkRevocationStatus();
    }

    @Test(expected = GeneralSecurityException.class)
    public void testCRLRevocation() throws GeneralSecurityException {
        CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                .revocation()
                .cRLEnabled(true)
                .cRLDPEnabled(false)
                .cRLLoader(new CertificateValidator.CRLLoaderProxy(_crl))
                .oCSPEnabled(false)
                .oCSPResponderURI("")
                .build(clientCertificates);
        validator.checkRevocationStatus();
    }

    @Test
    public void testCRLRevocationUsingDistributionPoint() throws GeneralSecurityException {
        // Pre-requisites: the certificate must have a distribution point extension
        // The test starts up a mock http server, extracts the distribution point URI
        // from the certificate, uses the DP to load CRL and verifies that certificate
        // has been revoked.
        try {
            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/dp")).respond(HttpResponse.response().withBody(_crl.getEncoded()).withStatusCode(200));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(true)
                    .cRLLoader(new CertificateValidator.CRLLoaderProxy(_crl))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);
            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), "Certificate has been revoked, certificate's subject: CN=Client");
        }
    }

    @Test
    public void testExceptionOnInvalidResponseFromCRLRevocationDP() throws GeneralSecurityException {
        // Pre-requisites: the certificate must have a distribution point extension
        // The test starts up a mock http server, extracts the distribution point URI
        // from the certificate, attemps to load CRL and upon receiving illegible
        // input throws an exception
        try {
            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/dp")).respond(HttpResponse.response().withBody("somebadinput".getBytes()).withStatusCode(200));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(true)
                    .cRLLoader(new CertificateValidator.CRLLoaderProxy(_crl))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);
            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception due to bad input.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), "Empty input");
        }
    }
    @Test
    public void testExceptionOnBadRequestFromCRLRevocationDP() throws GeneralSecurityException, MalformedURLException {
        // Pre-requisites: the certificate must have a distribution point extension
        // The test starts up a mock http server, extracts the distribution point URI
        // from the certificate, attemps to load CRL and upon receiving illegible
        // input throws an exception
        try {
            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/dp")).respond(HttpResponse.response().withBody("somebadinput".getBytes()).withStatusCode(400));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(true)
                    .cRLLoader(new CertificateValidator.CRLLoaderProxy(_crl))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);
            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception due to HTTP status 400 (Bad Request).");
        }
        catch(GeneralSecurityException e) {
            //http://localhost:9000/dp
            Assert.assertEquals(e.getMessage(), String.format("Unable to load CRL from \"%s\"", cRLdistributionPoint.toString()));
        }
    }

    @Test
    public void testLoadingCRLFromLdap() throws GeneralSecurityException, NamingException {
        try {
            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(false)
                    .cRLLoader(new CertificateValidator.CRLFileLoader("ldap://irrelevant",
                            new CertificateValidator.LdapContext(MockInitialDirContextFactory.class.getName())))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);

            Attributes mockAttributes = mock(Attributes.class);
            Attribute mockAttr = mock(Attribute.class);
            doReturn(mockAttributes).when(MockInitialDirContextFactory.getMockContext()).getAttributes(anyString(), any());
            doReturn(mockAttr).when(mockAttributes).get(eq("certificateRevocationList;binary"));
            doReturn(_crl.getEncoded()).when(mockAttr).get();

            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), "Certificate has been revoked, certificate's subject: CN=Client");
        }
    }

    @Test
    public void testExceptionOnBadCRLFromLdap() throws GeneralSecurityException, NamingException {
        try {
            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(false)
                    .cRLLoader(new CertificateValidator.CRLFileLoader("ldap://irrelevant",
                            new CertificateValidator.LdapContext(MockInitialDirContextFactory.class.getName())))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);

            Attributes mockAttributes = mock(Attributes.class);
            Attribute mockAttr = mock(Attribute.class);
            doReturn(mockAttributes).when(MockInitialDirContextFactory.getMockContext()).getAttributes(anyString(), any());
            doReturn(mockAttr).when(mockAttributes).get(eq("certificateRevocationList;binary"));
            doReturn("somebaddata".getBytes()).when(mockAttr).get();

            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), "Empty input");
        }
    }

    @Test
    public void testExceptionOnNullCRLFromLdap() throws GeneralSecurityException, NamingException {
        URI ldapUrl = URI.create("ldap://irrelevant");
        try {
            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(true)
                    .cRLDPEnabled(false)
                    .cRLLoader(new CertificateValidator.CRLFileLoader(ldapUrl.toString(),
                            new CertificateValidator.LdapContext(MockInitialDirContextFactory.class.getName())))
                    .oCSPEnabled(false)
                    .oCSPResponderURI("")
                    .build(clientCertificates);

            Attributes mockAttributes = mock(Attributes.class);
            Attribute mockAttr = mock(Attribute.class);
            doReturn(mockAttributes).when(MockInitialDirContextFactory.getMockContext()).getAttributes(anyString(), any());
            doReturn(mockAttr).when(mockAttributes).get(eq("certificateRevocationList;binary"));
            doReturn(null).when(mockAttr).get();

            validator.checkRevocationStatus();
            Assert.fail("CRL revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), String.format("Failed to download CRL from \"%s\"", ldapUrl.toString()));
        }
    }

    @Test
    public void testExceptionOnOCSPDoesNotSupportSelfSignedCertChecks() throws GeneralSecurityException, NamingException {
        try {
            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(false)
                    .cRLDPEnabled(false)
                    .cRLrelativePath(null)
                    .oCSPEnabled(true)
                    .oCSPResponderURI("")
                    .build(new X509Certificate[] { rootCertificate });

            validator.checkRevocationStatus();
            Assert.fail("OCSP revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            Assert.assertEquals(e.getMessage(), "OCSP requires a responder certificate. OCSP cannot be used to verify the revocation status of self-signed certificates.");
        }
    }
    @Test
    public void testOCSPWithResponderURIInAIA_IssuerPrincipalAsResponderId() throws GeneralSecurityException, NamingException, IOException, OperatorCreationException, OCSPException {
        try {
            OCSPResponse ocspResponse = generateCertificateCompromisedOCSPResponseIssuerPrincipalAsResponderId();
            byte[] ocspResponseBytes = ocspResponse.getEncoded();

            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/ocsp")).respond(HttpResponse.response().withBody(ocspResponseBytes).withStatusCode(200));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(false)
                    .cRLDPEnabled(false)
                    .cRLrelativePath(null)
                    .oCSPEnabled(true)
                    .oCSPResponderURI(null)
                    .build(clientCertificates);

            validator.checkRevocationStatus();
            Assert.fail("OCSP revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            String testMessage = "Certificate's been revoked.\nCRLReason: aACompromise";
            Assert.assertEquals(testMessage, e.getMessage().substring(0, testMessage.length()));
        }
    }

    @Test
    public void testOCSPWithResponderURIInAIA() throws GeneralSecurityException, NamingException, IOException, OperatorCreationException, OCSPException {
        try {
            OCSPResponse ocspResponse = generateCertificateCompromisedOCSPResponse();
            byte[] ocspResponseBytes = ocspResponse.getEncoded();

            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/ocsp")).respond(HttpResponse.response().withBody(ocspResponseBytes).withStatusCode(200));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(false)
                    .cRLDPEnabled(false)
                    .cRLrelativePath(null)
                    .oCSPEnabled(true)
                    .oCSPResponderURI(null)
                    .build(clientCertificates);

            validator.checkRevocationStatus();
            Assert.fail("OCSP revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            String testMessage = "Certificate's been revoked.\nCRLReason: aACompromise";
            Assert.assertEquals(testMessage, e.getMessage().substring(0, testMessage.length()));
        }
    }
    @Test
    public void testOCSPWithManuallySpecifiedResponderURI() throws GeneralSecurityException, NamingException, IOException, OperatorCreationException, OCSPException {
        try {
            OCSPResponse ocspResponse = generateCertificateCompromisedOCSPResponse();
            byte[] ocspResponseBytes = ocspResponse.getEncoded();

            // setting behaviour for test case
            mockServerClient.when(HttpRequest.request("/ocsp")).respond(HttpResponse.response().withBody(ocspResponseBytes).withStatusCode(200));

            CertificateValidator validator = new CertificateValidator.CertificateValidatorBuilder()
                    .revocation()
                    .cRLEnabled(false)
                    .cRLDPEnabled(false)
                    .cRLrelativePath(null)
                    .oCSPEnabled(true)
                    .oCSPResponderURI(ocspResponderUri.toString())
                    .build(clientCertificates);

            validator.checkRevocationStatus();
            Assert.fail("OCSP revocation check should have raised an exception.");
        }
        catch(GeneralSecurityException e) {
            String testMessage = "Certificate's been revoked.\nCRLReason: aACompromise";
            Assert.assertEquals(testMessage, e.getMessage().substring(0, testMessage.length()));
        }
    }

}
