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

package org.keycloak.broker.wsfed.readers;

import org.keycloak.broker.wsfed.SAML11RequestedToken;
import org.keycloak.broker.wsfed.writers.SAML11RequestedTokenWriter;
import org.keycloak.common.util.Base64;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.parsers.AbstractParser;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public class SAML11RequestedTokenParser extends AbstractParser {

    @Override
    public Object parse(XMLEventReader xmlEventReader) throws ParsingException {

        String wsFedResponse = null;
        SAML11AssertionType assertion = null;

        try {
            StartElement startElement = StaxParserUtil.getNextStartElement(xmlEventReader);
            StaxParserUtil.validate(startElement, SAML11RequestedTokenWriter.REQUESTED_TOKEN);
            while (xmlEventReader.hasNext()) {
                XMLEvent xmlEvent = StaxParserUtil.peek(xmlEventReader);
                if (xmlEvent == null)
                    break;
                if (xmlEvent instanceof EndElement) {
                    EndElement endElement = (EndElement) StaxParserUtil.getNextEvent(xmlEventReader);
                    String endElementName = StaxParserUtil.getEndElementName(endElement);
                    if (endElementName.equals(SAML11RequestedTokenWriter.REQUESTED_TOKEN))
                        break;
                    else
                        throw logger.parserUnknownEndElement(endElementName);
                }
                startElement = StaxParserUtil.peekNextStartElement(xmlEventReader);
                if (startElement == null)
                    break;
                String tag = StaxParserUtil.getStartElementName(startElement);
                if (tag.equals(SAML11RequestedTokenWriter.WSFEDRESPONSE_RAW)) {
                    StartElement element = StaxParserUtil.getNextStartElement(xmlEventReader);
                    wsFedResponse = new String(Base64.decode(StaxParserUtil.getElementText(xmlEventReader)));
                } else if (tag.equals(SAML11RequestedTokenWriter.ASSERTION)) {
                    StartElement element = StaxParserUtil.getNextStartElement(xmlEventReader);
                    String assertionText = new String(Base64.decode(StaxParserUtil.getElementText(xmlEventReader)));

                    byte[] bytes = assertionText.getBytes();
                    InputStream is = new ByteArrayInputStream(bytes);
                    Object respType = new SAMLParser().parse(is);
                    assertion = SAML11AssertionType.class.cast(respType);

                } else {
                    StaxParserUtil.bypassElementBlock(xmlEventReader, tag);
                }
            }
        }
        catch(IOException ex) {
            throw new RuntimeException(ex);
        }
        if (wsFedResponse == null || assertion == null) {
            throw new RuntimeException("Failed to parse wsfed saml2 requested token.");
        }
        return SAML11RequestedToken.createSAML11RequestedToken(wsFedResponse, assertion);
    }

    @Override
    public boolean supports(QName qname) {
        return false;
    }
}
