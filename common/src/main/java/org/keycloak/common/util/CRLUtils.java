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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @since 10/31/2016
 */

public final class CRLUtils {

    static {
        BouncyIntegration.init();
    }

    private static final String CRL_DISTRIBUTION_POINTS_OID = "2.5.29.31";

    /**
     * Retrieves a list of CRL distribution points from CRLDP v3 certificate extension
     * See <a href="www.nakov.com/blog/2009/12/01/x509-certificate-validation-in-java-build-and-verify-cchain-and-verify-clr-with-bouncy-castle/">CRL validation</a>
     * @param cert
     * @return
     * @throws IOException
     */
    public static List<String> getCRLDistributionPoints(X509Certificate cert) throws IOException {
        byte[] data = cert.getExtensionValue(CRL_DISTRIBUTION_POINTS_OID);
        if (data == null)
            return new ArrayList<>();

        List<String> dps = new LinkedList<>();
        ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(data));
        DEROctetString octetString = (DEROctetString)is.readObject();
        byte[] octets = octetString.getOctets();

        ASN1InputStream is2 = new ASN1InputStream(new ByteArrayInputStream(octets));
        CRLDistPoint crlDP = CRLDistPoint.getInstance(is2.readObject());

        for (DistributionPoint dp : crlDP.getDistributionPoints()) {
            DistributionPointName dpn = dp.getDistributionPoint();
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] names = GeneralNames.getInstance(dpn.getName()).getNames();
                for (GeneralName gn : names) {
                    if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(gn.getName()).getString();
                        dps.add(url);
                    }
                }
            }
        }

        return dps;
    }

}
