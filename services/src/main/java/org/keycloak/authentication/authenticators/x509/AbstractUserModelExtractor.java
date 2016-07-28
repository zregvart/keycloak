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

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
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
    static final String DEFAULT_CUSTOM_EXPRESSION = "CN=(.*?)(?:,|$)";
    static final String DEFAULT_MATCH_ALL_EXPRESSION = "(.*?)(?:$)";

    public abstract UserModel find(AuthenticationFlowContext context, X509Certificate[] certs);

    static abstract class UserIdentityExtractor {

        abstract Object extract(X509Certificate cert);
    }

    static abstract class UserIdentityMapper {

        abstract UserModel find(AuthenticationFlowContext context, Object userId) throws ModelDuplicateException;
    }

    static class UsernameOrEmailMapper extends UserIdentityMapper {

        UsernameOrEmailMapper() {
        }

        @Override
        UserModel find(AuthenticationFlowContext context, Object userId) throws ModelDuplicateException {

            if (userId == null) {
                logger.debug("[UsernameOrEmailMapper] userId is null.");
                return null;
            }

            UserModel user;
            try {
                context.getEvent().detail(Details.USERNAME, userId.toString());
                context.getClientSession().setNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, userId.toString());

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
        UserModel find(AuthenticationFlowContext context, Object userId) throws ModelDuplicateException {
            // TODO finish me
            logger.warn("[UserAttributeMapper] Not implemented");
            return null;
        }
    }

    static class CertificateThumbprintMapper extends UserIdentityMapper {

        @Override
        UserModel find(AuthenticationFlowContext context, Object userId) throws ModelDuplicateException {

            // TODO finish me
            logger.warn("[CertificateThumbprintMapper] Not implemented");
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
                logger.warnf("[SimpleIdentityExtractor] No matches were found for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            if (m.groupCount() != 1) {
                logger.warnf("[SimpleIdentityExtractor] Match produced more than a single group for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            return m.group(1);
        };
    }

    static class CertificateThumbprintExtractor extends UserIdentityExtractor {

        static final char[] hexifyChars = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

        @Override
        Object extract(X509Certificate cert) {

            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                byte[] encoded = cert.getEncoded();
                md.update(encoded);
                return hexify(md.digest());
            }
            catch(NoSuchAlgorithmException ex) {
                logger.errorf("[CertificateThumbprintExtractor] %s", ex.toString());
            }
            catch(CertificateEncodingException ex) {
                logger.errorf("[CertificateThumbprintExtractor] %s", ex.toString());
            }
            return null;
        }

        static String hexify(byte[] bytes) {
            StringBuffer sb = new StringBuffer();
            for (byte b : bytes) {
                sb.append(hexifyChars[(b & 0xf0) >> 4]);
                sb.append(hexifyChars[b & 0x0f]);
            }
            return sb.toString();
        }

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
        UserIdentityMapper userIdMapper = null;

        switch(userIdSource) {

            case MAPPING_SOURCE_CERT_SUBJECTDN:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getSubjectDN().getName());
                break;
            case MAPPING_SOURCE_CERT_ISSUERDN:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getIssuerDN().getName());
                break;
            case MAPPING_SOURCE_CERT_SERIALNUMBER:
                userIdExtractor = new SimpleIdentityExtractor(pattern, cert -> cert.getSerialNumber().toString());
                break;
            case MAPPING_SOURCE_CERT_THUMBPRINT:
                userIdExtractor = new CertificateThumbprintExtractor();
                userIdMapper = new CertificateThumbprintMapper();
                break;
            default:
                logger.warnf("[AbstractUserModelExtractor:fromConfig] Unknown or unsupported user identity source: \"%s\"", userIdSource);
                throw new Exception("Unknown or unsupported user identity source");
        }

        if (userIdMapper == null) {
            switch (userIdMapperType) {
                case USER_ATTRIBUTE_MAPPER:
                    userIdMapper = new UserAttributeMapper(attributeOrPropertyName);
                    break;
                case USER_PROPERTY_MAPPER:
                    userIdMapper = new UsernameOrEmailMapper();
                    break;
                default:
                    logger.warnf("[AbstractUserModelExtractor:fromConfig] Unknown or unsupported user identity mapper: \"%s\"", userIdMapperType);
                    throw new Exception("Unknown or unsupported user identity mapper");
            }
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
        public UserModel find(AuthenticationFlowContext context, X509Certificate[] certs) throws ModelDuplicateException {
            return _userIdMapper.find(context, _useridExtractor.extract(certs[0]));
        }
    }

}
