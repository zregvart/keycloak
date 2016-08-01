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

import org.keycloak.services.ServicesLogger;

import java.security.cert.X509Certificate;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/30/2016
 */

public abstract class UserIdentityExtractor {

    private static final ServicesLogger logger = ServicesLogger.ROOT_LOGGER;

    public abstract Object extractUserIdentity(X509Certificate[] certs);

    static class PatternMatcher extends UserIdentityExtractor {
        private final String _pattern;
        private final Function<X509Certificate[],String> _f;
        PatternMatcher(String pattern, Function<X509Certificate[],String> valueToMatch) {
            _pattern = pattern;
            _f = valueToMatch;
        }

        @Override
        public Object extractUserIdentity(X509Certificate[] certs) {
            String value = _f.apply(certs);

            Pattern r = Pattern.compile(_pattern, Pattern.CASE_INSENSITIVE);

            Matcher m = r.matcher(value);

            if (!m.find()) {
                logger.warnf("[PatternMatcher:extract] No matches were found for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            if (m.groupCount() != 1) {
                logger.warnf("[PatternMatcher:extract] Match produced more than a single group for input \"%s\", pattern=\"%s\"", value, _pattern);
                return null;
            }

            return m.group(1);
        }
    }

    public static UserIdentityExtractor getPatternIdentityExtractor(String pattern,
                                                                 Function<X509Certificate[],String> func) {
        return new PatternMatcher(pattern, func);
    }
}
