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

package org.keycloak.broker.wsfed;

import org.keycloak.broker.provider.DefaultDataMarshaller;
import org.keycloak.broker.wsfed.readers.SAML2RequestedTokenParser;
import org.keycloak.broker.wsfed.writers.SAML2RequestedTokenWriter;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

/**
 *
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/1/2016
 */
public class RSTDataMarshaller extends DefaultDataMarshaller {

    @Override
    public String serialize(Object obj) {
        if (obj.getClass().getName().startsWith("org.keycloak.broker.wsfed")) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            try {
                if (obj instanceof SAML2RequestedToken) {
                    SAML2RequestedToken requestedToken = (SAML2RequestedToken) obj;
                    SAML2RequestedTokenWriter writer = new SAML2RequestedTokenWriter(StaxUtil.getXMLStreamWriter(bos));
                    writer.write(requestedToken);
                } else {
                    throw new IllegalArgumentException("Don't know how to serialize object of type " + obj.getClass().getName());
                }
            }
            catch(ProcessingException ex) {
                throw new RuntimeException(ex);
            }
            return new String(bos.toByteArray());
        } else {
            return super.serialize(obj);
        }
    }
    @Override
    public <T> T deserialize(String serialized, Class<T> clazz) {
        if (clazz.getName().startsWith("org.keycloak.broker.wsfed")) {
            String xmlString = serialized;

            try {
                if (clazz.equals(SAML2RequestedToken.class)) {
                    byte[] bytes = xmlString.getBytes();
                    InputStream is = new ByteArrayInputStream(bytes);
                    Object respType = new SAML2RequestedTokenParser().parse(is);
                    return clazz.cast(respType);
                } else {
                    throw new IllegalArgumentException("Don't know how to deserialize object of type " + clazz.getName());
                }
            } catch (ParsingException pe) {
                throw new RuntimeException(pe);
            }

        } else {
            return super.deserialize(serialized, clazz);
        }
    }
}
