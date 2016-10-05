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

package org.keycloak.protocol.wsfed.builders;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v1.assertion.*;
import org.keycloak.dom.saml.v2.assertion.ConditionsType;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.exceptions.fed.IssueInstantMissingException;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.net.URI;
import java.util.GregorianCalendar;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/4/2016
 */

public class SAML11AssertionTypeBuilder {
    protected static final Logger logger = Logger.getLogger(SAML11AssertionTypeBuilder.class);

    private static final String ATTRIBUTE_NAMESPACE = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims";

    private final static long CLOCK_SKEW = 2000; // in milliseconds

    protected String requestID;
    protected String issuer;
    protected String requestIssuer;
    protected int subjectExpiration;
    protected int assertionExpiration;
    protected String nameId;
    protected String nameIdFormat;

    public SAML11AssertionTypeBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    /**
     * Length of time in seconds the subject can be confirmed
     * See SAML core specification 2.4.1.2 NotOnOrAfter
     *
     * @param subjectExpiration Number of seconds the subject should be valid
     * @return
     */
    public SAML11AssertionTypeBuilder subjectExpiration(int subjectExpiration) {
        this.subjectExpiration = subjectExpiration;
        return this;
    }

    /**
     * Length of time in seconds the assertion is valid for
     * See SAML core specification 2.5.1.2 NotOnOrAfter
     *
     * @param assertionExpiration Number of seconds the assertion should be valid
     * @return
     */
    public SAML11AssertionTypeBuilder assertionExpiration(int assertionExpiration) {
        this.assertionExpiration = assertionExpiration;
        return this;
    }

    public SAML11AssertionTypeBuilder requestID(String requestID) {
        this.requestID =requestID;
        return this;
    }

    public SAML11AssertionTypeBuilder requestIssuer(String requestIssuer) {
        this.requestIssuer =requestIssuer;
        return this;
    }

    public SAML11AssertionTypeBuilder nameIdentifier(String nameIdFormat, String nameId) {
        this.nameIdFormat = nameIdFormat;
        this.nameId = nameId;
        return this;
    }

    protected SAML11AttributeType getNameAttribute(String nameId) {
        SAML11AttributeType nameAttribute = new SAML11AttributeType("name", URI.create(ATTRIBUTE_NAMESPACE));
        nameAttribute.add(nameId);
        return nameAttribute;
    }

    protected SAML11SubjectType getSubjectType() {
        SAML11SubjectConfirmationType subjectConfirmationType = new SAML11SubjectConfirmationType();
        subjectConfirmationType.addConfirmationMethod(URI.create("urn:oasis:names:tc:SAML:1.0:cm:bearer"));

        SAML11SubjectType subject = new SAML11SubjectType();
        subject.setSubjectConfirmation(subjectConfirmationType);

        return subject;
    }

    public SAML11AssertionType buildModel() throws ConfigurationException, ProcessingException, DatatypeConfigurationException {
        String id = IDGenerator.create("ID_");

        XMLGregorianCalendar issuerInstant = XMLTimeUtil.getIssueInstant();
        SAML11AssertionType assertion = AssertionUtil.createSAML11Assertion(id, issuerInstant, issuer);

        //Add request issuer as the audience restriction
        SAML11AudienceRestrictionCondition audience = new SAML11AudienceRestrictionCondition();
        audience.add(URI.create(requestIssuer));

        SAML11ConditionsType conditions;
        if (assertionExpiration <= 0) {
            conditions = new SAML11ConditionsType();

            XMLGregorianCalendar beforeInstant = XMLTimeUtil.subtract(issuerInstant, CLOCK_SKEW);
            conditions.setNotBefore(beforeInstant);

            XMLGregorianCalendar assertionValidityLength = XMLTimeUtil.add(issuerInstant, CLOCK_SKEW);
            conditions.setNotOnOrAfter(assertionValidityLength);
        } else {
            try {
                AssertionUtil.createSAML11TimedConditions(assertion, assertionExpiration * 1000, CLOCK_SKEW);
                conditions = assertion.getConditions();
            }
            catch(IssueInstantMissingException ex) {
                throw new RuntimeException(ex);
            }
        }
        if (conditions == null) {
            throw new RuntimeException("Failed to create timed conditions");
        }
        conditions.add(audience);
        assertion.setConditions(conditions);

        SAML11SubjectType subject = getSubjectType();

        SAML11AttributeStatementType attributeStatement = new SAML11AttributeStatementType();
        attributeStatement.setSubject(subject);
        attributeStatement.add(getNameAttribute(nameId));
        assertion.add(attributeStatement);

        SAML11AuthenticationStatementType authnStatement = getAuthenticationStatement(subject, assertion.getIssueInstant());
        assertion.add(authnStatement);

        return assertion;
    }
    protected XMLGregorianCalendar getXMLGregorianCalendarNow() throws DatatypeConfigurationException
    {
        GregorianCalendar gregorianCalendar = new GregorianCalendar();
        DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
        XMLGregorianCalendar now =
                datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
        return now;
    }

    protected SAML11AuthenticationStatementType getAuthenticationStatement(SAML11SubjectType subject, XMLGregorianCalendar authenticationInstant) {

        SAML11AuthenticationStatementType authnStatement = new SAML11AuthenticationStatementType(URI.create(JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get()), authenticationInstant);
        authnStatement.setSubject(subject);
        return authnStatement;
    }
}
