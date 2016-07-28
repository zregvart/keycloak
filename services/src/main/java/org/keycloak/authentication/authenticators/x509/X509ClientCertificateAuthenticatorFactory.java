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

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ServicesLogger;

import java.util.LinkedList;
import java.util.List;

import static java.util.Arrays.asList;

import static org.keycloak.authentication.authenticators.x509.AbstractUserModelExtractor.DEFAULT_CUSTOM_EXPRESSION;
import static org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator.*;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;
import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;


/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 *
 */
public class X509ClientCertificateAuthenticatorFactory implements AuthenticatorFactory {

    protected static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;
    public static final String PROVIDER_ID = "auth-x509-client-certificate";
    public static final X509ClientCertificateAuthenticator SINGLETON =
            new X509ClientCertificateAuthenticator();

    private static final String[] mappingSources = {
            MAPPING_SOURCE_CERT_SUBJECTDN,
            MAPPING_SOURCE_CERT_ISSUERDN,
            MAPPING_SOURCE_CERT_THUMBPRINT,
            MAPPING_SOURCE_CERT_SERIALNUMBER
    };

    private static final String[] userModelMappers = {
            USER_ATTRIBUTE_MAPPER,
            USER_PROPERTY_MAPPER
    };

    private static final String[] certificateRevocationCheckingTypes = {
            NO_CERT_CHECKING,
            ENABLE_CRL,
            ENABLE_OCSP
    };

    protected static final List<ProviderConfigProperty> configProperties;
    static {
        List<String> mappingSourceTypes = new LinkedList<>();
        for (String s : mappingSources) {
            mappingSourceTypes.add(s);
        }
        ProviderConfigProperty mappingMethodList = new ProviderConfigProperty();
        mappingMethodList.setType(ProviderConfigProperty.LIST_TYPE);
        mappingMethodList.setName(MAPPING_SOURCE_SELECTION);
        mappingMethodList.setLabel("User Identity Source");
        mappingMethodList.setHelpText("Choose how to extract user identity from X509 certificate or the certificate fields. For example, SubjectDN will match the custom regular expression specified below to the value of certificate's SubjectDN field.");
        mappingMethodList.setDefaultValue(mappingSourceTypes);

        ProviderConfigProperty regExp = new ProviderConfigProperty();
        regExp.setType(STRING_TYPE);
        regExp.setName(REGULAR_EXPRESSION);
        regExp.setDefaultValue(DEFAULT_CUSTOM_EXPRESSION);
        regExp.setLabel("A regular expression to extract user identity");
        regExp.setHelpText("The regular expression to extract a user identity. The expression must contain a single group. For example, 'uniqueId=(.*?)(?:,|$)' will match 'uniqueId=somebody@company.org, CN=somebody' and give somebody@company.org");

        List<String> mapperTypes = new LinkedList<>();
        for (String m : userModelMappers) {
            mapperTypes.add(m);
        }

        ProviderConfigProperty userMapperList = new ProviderConfigProperty();
        userMapperList.setType(ProviderConfigProperty.LIST_TYPE);
        userMapperList.setName(USER_MAPPER_SELECTION);
        userMapperList.setHelpText("Choose how to map extracted user identities to users");
        userMapperList.setLabel("User mapping method");
        userMapperList.setDefaultValue(mapperTypes);

        ProviderConfigProperty attributeOrPropertyValue = new ProviderConfigProperty();
        attributeOrPropertyValue.setType(STRING_TYPE);
        attributeOrPropertyValue.setName(USER_MAPPER_VALUE);
        attributeOrPropertyValue.setLabel("A name of user property or attribute");
        attributeOrPropertyValue.setHelpText("A name of user property or attribute");

        List<String> revocationMethodTypes = new LinkedList<>();
        for (String m : certificateRevocationCheckingTypes) {
            revocationMethodTypes.add(m);
        }

        ProviderConfigProperty checkRevocationMethod = new ProviderConfigProperty();
        checkRevocationMethod.setType(ProviderConfigProperty.LIST_TYPE);
        checkRevocationMethod.setName(CERTIFICATE_CHECK_REVOCATION_METHOD);
        checkRevocationMethod.setHelpText("Choose how to or whether to check for X509 certificate revocation. CRL means that certificate revocation list will be used to check for certificate revocation, OCSP will use online certificate status protocol.");
        checkRevocationMethod.setLabel("Certificate Revocation Checking Strategy");
        checkRevocationMethod.setDefaultValue(revocationMethodTypes);

        ProviderConfigProperty crlDPEnabled = new ProviderConfigProperty();
        crlDPEnabled.setType(BOOLEAN_TYPE);
        crlDPEnabled.setName(ENABLE_CRLDP);
        crlDPEnabled.setDefaultValue(false);
        crlDPEnabled.setLabel("Enable Certificate Revocation List Distribution Point to check certificate revocation status");
        crlDPEnabled.setHelpText("CRL Distribution Point is a starting point for CRL. CDP is optional, but most PKI authorities include CDP in their certificates.");

        ProviderConfigProperty ocspResponderUri = new ProviderConfigProperty();
        ocspResponderUri.setType(STRING_TYPE);
        ocspResponderUri.setName(OCSPRESPONDER_URI);
        ocspResponderUri.setLabel("OCSP Responder Uri");
        ocspResponderUri.setHelpText("Clients use OCSP Responder Uri to check certificate revocation status. This value is required if the Certificate Revocation Checking Method is set to OCSP");

        ProviderConfigProperty showChallengeResponse = new ProviderConfigProperty();
        showChallengeResponse.setType(BOOLEAN_TYPE);
        showChallengeResponse.setName(SHOW_CHALLENGE_RESPONSE);
        showChallengeResponse.setLabel("Require Authentication Confirmation");
        showChallengeResponse.setHelpText("Display authentication details, whether authentication succeeded or failed. Users will also be prompted to choose whether to continue with the identity chosen based on the contents of the certificate.");

        configProperties = asList(mappingMethodList, regExp, userMapperList, attributeOrPropertyValue, checkRevocationMethod, crlDPEnabled, ocspResponderUri, showChallengeResponse);
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };


    @Override
    public String getHelpText() {
        return "Sign in users by looking up user to x509 certificate association";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        logger.info("[X509ClientCertificateAuthenticatorFactory] getConfigProperties");
        return configProperties;
    }

    @Override
    public String getDisplayType() {
        return "X509 client certificate authentication";
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.CLIENT_CERT;
    }

    @Override
    public boolean isConfigurable() {
        logger.info("[X509ClientCertificateAuthenticatorFactory] isConfigurable");
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        logger.info("[X509ClientCertificateAuthenticatorFactory] isUserSetupAllowed");
        return false;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {
        logger.info("[X509ClientCertificateAuthenticatorFactory] init");

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        logger.info("[X509ClientCertificateAuthenticatorFactory] postInit");

    }

    @Override
    public void close() {
        logger.info("[X509ClientCertificateAuthenticatorFactory] close");

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
