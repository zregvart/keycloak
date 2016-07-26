package org.keycloak.authentication.authenticators.x509;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.keycloak.authentication.authenticators.x509.X509ClientCertificateAuthenticator.*;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/22/2016
 */

public abstract class AbstractUserModelExtractor {

    private static ServicesLogger logger = ServicesLogger.ROOT_LOGGER;
    //static final String SUBJECTDN_CN_PATTERN = "CN=(.*?)(?:,|$)";
    //static final String SUBJECTDN_EMAILADDRESS_PATTERN = "emailAddress=(.*?)(?:,|$)";
    static final String DEFAULT_CUSTOM_EXPRESSION = "CN=(.*?)(?:,|$)";
    static final String DEFAULT_MATCH_ALL_EXPRESSION = "(.*?)(?:$)";

    public abstract UserModel find(AuthenticationFlowContext context, X509Certificate[] certs);

    static abstract class UserIdentityExtractor {

        abstract Object extract(X509Certificate cert);
    }

    static abstract class UserIdentityMapper {

        abstract UserModel find(AuthenticationFlowContext context, Object userId);
    }

    static class UserPropertyMapper extends UserIdentityMapper {

        private String _userPropertyName;
        UserPropertyMapper(String userPropertyName) {
            _userPropertyName = userPropertyName;
        }

        @Override
        UserModel find(AuthenticationFlowContext context, Object userId) {
            UserModel user;
            try {
                user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), userId.toString().trim());
            } catch (ModelDuplicateException ex) {
                logger.modelDuplicateException(ex);
                throw ex;
            }
            return user;
        }
    }

    static class UserAttributeMapper extends UserIdentityMapper {

        private String _userAttributeName;
        UserAttributeMapper(String userAttributeName) {
            _userAttributeName = userAttributeName;
        }

        @Override
        UserModel find(AuthenticationFlowContext context, Object userId) {
            return null;
        }
    }

    static class SimpleIdentityExtractor extends UserIdentityExtractor {

        private String _pattern;
        private Function<X509Certificate, String> _getter;

        SimpleIdentityExtractor(String pattern, Function<X509Certificate, String> getter) {
            _pattern = pattern;
            _getter = getter;
        }

        @Override
        Object extract(X509Certificate cert) {

            ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

            String value = _getter.apply(cert);

            Pattern r = Pattern.compile(_pattern, Pattern.CASE_INSENSITIVE);

            Matcher m = r.matcher(value);

            if (!m.find()) {
                logger.warnf("[Anonymous] No matches were found for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            if (m.groupCount() != 1) {
                logger.warnf("[Anonymous] Match produced more than a single group for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            return m.group(1);
        };
    }

    public static AbstractUserModelExtractor fromConfig(Map<String,String> parameters) throws Exception {

        String userIdSource;
        if ((userIdSource = parameters.get(MAPPING_SOURCE_SELECTION)) == null) {
            userIdSource = MAPPING_SOURCE_CERT_SUBJECTDN;
        }

        String pattern;
        if ((pattern = parameters.get(REGULAR_EXPRESSION)) == null) {
            pattern = DEFAULT_MATCH_ALL_EXPRESSION;
        }

        String userIdMapperType;
        if ((userIdMapperType = parameters.get(USER_MAPPER_SELECTION)) == null) {
            userIdMapperType = USER_PROPERTY_MAPPER;
        }

        String attributeOrPropertyName;
        if ((attributeOrPropertyName = parameters.get(USER_MAPPER_VALUE)) == null) {
            attributeOrPropertyName = "userName";
        }


        UserIdentityExtractor userIdExtractor;
        switch(userIdSource.toLowerCase()) {

            case MAPPING_SOURCE_CERT_SUBJECTDN:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getSubjectDN().getName());
                break;
            case MAPPING_SOURCE_CERT_ISSUERDN:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getIssuerDN().getName());
                break;
            case MAPPING_SOURCE_CERT_SERIALNUMBER:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getSerialNumber().toString());
                break;
            default:
                logger.warnf("[AbstractUserModelExtractor:fromConfig] Unknown or unsupported user id source: \"%s\"", userIdSource);
                throw new Exception("Unknown or unsupported user id source");
        }

        UserIdentityMapper userIdMapper;
        switch(userIdMapperType.toLowerCase()) {
            case USER_ATTRIBUTE_MAPPER:
                userIdMapper = new UserAttributeMapper(attributeOrPropertyName);
                break;
            case USER_PROPERTY_MAPPER:
                userIdMapper = new UserPropertyMapper(attributeOrPropertyName);
                break;
            default:
                logger.warnf("[AbstractUserModelExtractor:fromConfig] Unknown or unsupported user id mapper: \"%s\"", userIdMapperType);
                throw new Exception("Unknown or unsupported user id mapper");
        }
        return new UserModelExtractor(userIdExtractor, userIdMapper);
    }


    private static class UserModelExtractor extends AbstractUserModelExtractor {

        private UserIdentityExtractor _useridExtractor;
        private UserIdentityMapper _userIdMapper;

        UserModelExtractor(UserIdentityExtractor userid, UserIdentityMapper mapper) {
            _useridExtractor = userid;
            _userIdMapper = mapper;
        }

        @Override
        public UserModel find(AuthenticationFlowContext context, X509Certificate[] certs) {
            return _userIdMapper.find(context, _useridExtractor.extract(certs[0]));
        }
    }

}
