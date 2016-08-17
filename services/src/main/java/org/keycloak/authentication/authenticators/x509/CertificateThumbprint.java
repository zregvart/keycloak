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

package org.keycloak.authentication.authenticators.x509;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/31/2016
 */

public final class CertificateThumbprint {

    static final char[] hexifyChars = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private static String hexify(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (byte b : bytes) {
            sb.append(hexifyChars[(b & 0xf0) >> 4]);
            sb.append(hexifyChars[b & 0x0f]);
        }
        return sb.toString();
    }

    public static String computeDigest(X509Certificate[] certs) throws NoSuchAlgorithmException, CertificateEncodingException {

        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] encoded = certs[0].getEncoded();
        md.update(encoded);
        return hexify(md.digest());
    }
}
