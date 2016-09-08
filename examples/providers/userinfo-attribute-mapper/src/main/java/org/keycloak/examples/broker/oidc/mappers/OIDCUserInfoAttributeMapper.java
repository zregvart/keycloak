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
package org.keycloak.examples.broker.oidc.mappers;

import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.oidc.KeycloakOIDCIdentityProviderFactory;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * OIDC UserInfo attribute mapper imports declared claim if it exists in the set of claims returned with the OIDC /userinfo endpoint
 * into the specified user property or attribute
 *
 * @author <a href="mailto:pnalyvayko@agi.com">Peter Nalyvayko</a>
 */
public class OIDCUserInfoAttributeMapper extends AbstractJsonUserAttributeMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {KeycloakOIDCIdentityProviderFactory.PROVIDER_ID, OIDCIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property;
        ProviderConfigProperty property1;
        property1 = new ProviderConfigProperty();
        property1.setName(CONF_JSON_FIELD);
        property1.setLabel("Claim");
        property1.setHelpText("Name of claim to search for in User info claim set.  You can reference nested claims using a '.', i.e. 'address.locality'.");
        property1.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property1);
        property = new ProviderConfigProperty();
        property.setName(CONF_USER_ATTRIBUTE);
        property.setLabel("UserInfo Attribute Name");
        property.setHelpText("User info attribute name to store claim.  Use email, lastName, and firstName to map to those predefined user properties.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(property);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }


    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getId() {
        return "oidc-userinfo-attribute-idp-mapper";
    }

    @Override
    public String getDisplayCategory() {
        return "UserInfo Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "UserInfo Attribute Importer";
    }

    @Override
    public String getHelpText() {
        return "Import declared claim if it exists in the set of claims returned with the OIDC /userinfo endpoint into the specified user property or attribute.";
    }

}
