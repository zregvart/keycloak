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

import org.junit.BeforeClass;
import org.keycloak.authentication.authenticators.x509.CertificateThumbprint;
import org.keycloak.common.util.CertificateUtils;

import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/14/2016
 */

public abstract class AbstractX509Test {
    protected static X509Certificate[] certificates;
    protected static KeyPair idpPair;
    protected static String certificateFingerprint;


    protected static X509Certificate generateTestCertificate(String subject, KeyPair pair) throws InvalidKeyException,
            NoSuchProviderException, SignatureException {

        X509Certificate certificate = null;
        try {
            certificate = CertificateUtils.generateV1SelfSignedCertificate(pair, subject);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return certificate;
    }

    @BeforeClass
    public static void setupCerts() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, CertificateEncodingException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        idpPair = generator.generateKeyPair();
        certificates = new X509Certificate[] {generateTestCertificate("IDP", idpPair)};
        certificateFingerprint = CertificateThumbprint.computeDigest(new X509Certificate[] {certificates[0]});
    }
}
