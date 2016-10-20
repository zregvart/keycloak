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

package org.keycloak.common.util;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Create V3 certificates with optional V3 extensions.
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/19/2016
 */
public final class CertificateBuilder {
    static {
        BouncyIntegration.init();
    }

    private final PrivateKey caPrivateKey;
    private final X509v3CertificateBuilder certGen;
    public CertificateBuilder(KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCert,
                              String subject) throws NoSuchAlgorithmException, CertIOException, OperatorCreationException {
        this.caPrivateKey = caPrivateKey;
        this.certGen = createV3CertBuilder(keyPair, caCert, subject);
        addBasicConstraintsExtension(true);
    }

    private X509v3CertificateBuilder createV3CertBuilder(KeyPair keyPair, X509Certificate caCert, String subject) throws NoSuchAlgorithmException, OperatorCreationException, CertIOException {

        X500Name subjectDN = new X500Name("CN=" + subject);

        // Serial Number
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));

        // Validity
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + (((1000L * 60 * 60 * 24 * 30)) * 12) * 3);

        // SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(keyPair.getPublic()
                .getEncoded()));

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(caCert.getSubjectDN().getName()),
                serialNumber, notBefore, notAfter, subjectDN, subjPubKeyInfo);


        DigestCalculator digCalc = new BcDigestCalculatorProvider()
                .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);

        // Subject Key Identifier
        certGen.addExtension(Extension.subjectKeyIdentifier, false,
                x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

        // Authority Key Identifier
        certGen.addExtension(Extension.authorityKeyIdentifier, false,
                x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));

        return certGen;
    }

    public CertificateBuilder addBasicConstraintsExtension(boolean critical) throws CertIOException {
        // Basic Constraints
        certGen.addExtension(Extension.basicConstraints, critical, new BasicConstraints(0));
        return this;
    }

    public CertificateBuilder addKeyUsageExtension(boolean critical) throws CertIOException {
        // Key Usage
        this.certGen.addExtension(Extension.keyUsage, critical, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign
                | KeyUsage.cRLSign));
        return this;
    }

    public CertificateBuilder addExtendedKeyUsageExtension(boolean critical) throws CertIOException {
        // Extended Key Usage
        KeyPurposeId[] EKU = new KeyPurposeId[2];
        EKU[0] = KeyPurposeId.id_kp_emailProtection;
        EKU[1] = KeyPurposeId.id_kp_serverAuth;

        certGen.addExtension(Extension.extendedKeyUsage, critical, new ExtendedKeyUsage(EKU));
        return this;
    }

    public CertificateBuilder addCRLDistributionPointsExtension(URI cRLDistributionPoint) throws CertIOException {

        // CRL Distribution Points
        DERIA5String derString = new DERIA5String(cRLDistributionPoint.toString());
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, derString);
        GeneralNames generalNames= new GeneralNames(gn);
        DistributionPointName dpName = new DistributionPointName(generalNames);
        DistributionPoint dp = new DistributionPoint(dpName, null, null);
        DERSequence seq =  new DERSequence(dp);

        certGen.addExtension(Extension.cRLDistributionPoints, false, seq);
        return this;
    }

    public CertificateBuilder addOCSPResponderExtension(URI ocspResponderUri) throws IOException {

        // OCSP Responder URI is stored in AIA extension
        DERIA5String derString = new DERIA5String(ocspResponderUri.toString());
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, derString);
        AuthorityInformationAccess aia = new AuthorityInformationAccess(AccessDescription.id_ad_ocsp, gn);
        byte[] bytes = aia.toASN1Primitive().getEncoded();

        certGen.addExtension(Extension.authorityInfoAccess, false, aia);
        return this;
    }

    public X509Certificate build() throws OperatorCreationException, CertificateException {
        // Content Signer
        ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSAEncryption").setProvider("BC").build(caPrivateKey);

        // Certificate
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certGen.build(sigGen));
    }
}
