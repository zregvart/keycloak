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

package org.keycloak.broker.wsfed.writers;

import org.keycloak.broker.wsfed.SAML2RequestedToken;
import org.keycloak.common.util.Base64;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;

import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayOutputStream;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/2/2016
 */

public class SAML2RequestedTokenWriter {

    public final static String REQUESTED_TOKEN_PREFIX = "my";
    public final static String REQUESTED_TOKEN = "RequestedToken";
    public final static String REQUESTED_TOKEN_NSURI = "urn:my:names:tc:SAML:2.0:requestedtoken";
    public final static String WSFEDRESPONSE_RAW = "WsFedResponse";
    public final static String ASSERTION = "Assertion";
    protected XMLStreamWriter writer = null;

    public SAML2RequestedTokenWriter(XMLStreamWriter writer) {
        this.writer = writer;
    }

    public void write(SAML2RequestedToken requestedToken) throws ProcessingException {

        StaxUtil.writeStartElement(writer, REQUESTED_TOKEN_PREFIX, REQUESTED_TOKEN, REQUESTED_TOKEN_NSURI);
        StaxUtil.writeNameSpace(writer, REQUESTED_TOKEN_PREFIX, REQUESTED_TOKEN_NSURI);
        StaxUtil.writeDefaultNameSpace(writer, REQUESTED_TOKEN_NSURI);

        StaxUtil.writeStartElement(writer, REQUESTED_TOKEN_PREFIX, WSFEDRESPONSE_RAW, REQUESTED_TOKEN_NSURI);
        StaxUtil.writeCharacters(writer, Base64.encodeBytes(requestedToken.getWsFedResponse().getBytes()));
        StaxUtil.writeEndElement(writer);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        AssertionType assertion = requestedToken.getAssertionType();
        SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
        samlWriter.write(assertion);

        String samlAssertion = Base64.encodeBytes(bos.toByteArray());
        StaxUtil.writeStartElement(writer, REQUESTED_TOKEN_PREFIX, ASSERTION, REQUESTED_TOKEN_NSURI);
        StaxUtil.writeCharacters(writer, samlAssertion);
        StaxUtil.writeEndElement(writer);

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }
}
