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
//        ProviderConfigProperty subjectDnMethod = new ProviderConfigProperty();
//        subjectDnMethod.setType(STRING_TYPE);
//        subjectDnMethod.setName(MAPPING_SOURCE_CERT_SUBJECTDN);
//        subjectDnMethod.setLabel("Use SubjectDN to extract user identity");
//        subjectDnMethod.setHelpText("Extracts user identity from X509 Certificate Subject's Distinquished Name and maps it to existing user.");
//
//        ProviderConfigProperty issuerDnMethod = new ProviderConfigProperty();
//        issuerDnMethod.setType(STRING_TYPE);
//        issuerDnMethod.setName(MAPPING_SOURCE_CERT_ISSUERDN);
//        issuerDnMethod.setLabel("Use IssuerDN to extract user identity");
//        issuerDnMethod.setHelpText("Extracts user identity from X509 Certificate Issuer Distinquished Name and maps it to existing user.");
//
//        ProviderConfigProperty thumbprintMethod = new ProviderConfigProperty();
//        thumbprintMethod.setType(STRING_TYPE);
//        thumbprintMethod.setName(MAPPING_SOURCE_CERT_THUMBPRINT);
//        thumbprintMethod.setLabel("Identity based on X509 Certificate Thumbprint");
//        thumbprintMethod.setHelpText("Maps X509 Certificate thumbprint to existing user");
//
//        ProviderConfigProperty serialNumberMethod = new ProviderConfigProperty();
//        serialNumberMethod.setType(STRING_TYPE);
//        serialNumberMethod.setName(MAPPING_SOURCE_CERT_SERIALNUMBER);
//        serialNumberMethod.setLabel("Maps X509 Certificate serial number to existing user");
//        serialNumberMethod.setHelpText("Certificate's serial number is mapped to existing user");
//
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

//        ProviderConfigProperty attributeName = new ProviderConfigProperty();
//        attributeName.setType(STRING_TYPE);
//        attributeName.setName(USER_ATTRIBUTE_MAPPER);
//        attributeName.setLabel("Map user identity to user attribute");
//        attributeName.setHelpText("Match the user attribute to extracted user identity");
//
//        ProviderConfigProperty propertyName = new ProviderConfigProperty();
//        propertyName.setType(STRING_TYPE);
//        propertyName.setName(USER_PROPERTY_MAPPER);
//        propertyName.setLabel("Map user identity to User Property");
//        propertyName.setHelpText("Match the user property (e-mail, userName, etc.) to extracted user identity");

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
        //attributeOrPropertyValue.setDefaultValue("email");
        attributeOrPropertyValue.setLabel("A name of user property or attribute");
        attributeOrPropertyValue.setHelpText("A name of user property or attribute");

//        ProviderConfigProperty noCertChecking = new ProviderConfigProperty();
//        noCertChecking.setType(STRING_TYPE);
//        noCertChecking.setName(NO_CERT_CHECKING);
//        noCertChecking.setLabel("No Certificate Revocation Checking");
//        noCertChecking.setHelpText("No certificate revocation checking will be performed.");
//
//        ProviderConfigProperty crlEnabled = new ProviderConfigProperty();
//        crlEnabled.setType(STRING_TYPE);
//        crlEnabled.setName(ENABLE_CRL);
//        crlEnabled.setLabel("Enable Certificate Revocation List checking");
//        crlEnabled.setHelpText("Uses Performs certificate recovation list to check whether X509 client certificate has been revoked.");
//
//        ProviderConfigProperty ocspEnabled = new ProviderConfigProperty();
//        ocspEnabled.setType(STRING_TYPE);
//        ocspEnabled.setName(ENABLE_OCSP );
//        ocspEnabled.setLabel("Enable Online Certificate Status Protocol");
//        ocspEnabled.setHelpText("Use Online Certificate Status Protocol (OCSP) to check whether certificate has been revoked.");

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

        configProperties = asList(mappingMethodList, regExp, userMapperList, attributeOrPropertyValue, checkRevocationMethod, crlDPEnabled, ocspResponderUri);
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
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
