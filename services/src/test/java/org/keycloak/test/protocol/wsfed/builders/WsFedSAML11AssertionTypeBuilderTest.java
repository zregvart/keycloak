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

package org.keycloak.test.protocol.wsfed.builders;

import org.junit.Before;
import org.junit.Test;
import org.keycloak.dom.saml.v1.assertion.SAML11AssertionType;
import org.keycloak.dom.saml.v1.assertion.SAML11AttributeStatementType;
import org.keycloak.dom.saml.v1.assertion.SAML11AudienceRestrictionCondition;
import org.keycloak.dom.saml.v1.assertion.SAML11AuthenticationStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.wsfed.mappers.WSFedSAMLAttributeStatementMapper;
import org.keycloak.protocol.wsfed.mappers.WSFedSAMLRoleListMapper;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.test.common.MockHelper;
import org.keycloak.test.common.TestHelpers;
import org.mockito.MockitoAnnotations;
import org.keycloak.protocol.wsfed.builders.WsFedSAML11AssertionTypeBuilder;

import java.net.URI;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.keycloak.protocol.wsfed.builders.SAML11AssertionTypeBuilder.CLOCK_SKEW;
import static org.keycloak.protocol.wsfed.builders.WsFedSAMLAssertionTypeAbstractBuilder.WSFED_NAME_ID;
import static org.keycloak.protocol.wsfed.builders.WsFedSAMLAssertionTypeAbstractBuilder.WSFED_NAME_ID_FORMAT;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.any;

/**
 * @author <a href="mailto:brat000012001@gmail.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 10/8/2016
 */

public class WsFedSAML11AssertionTypeBuilderTest {

    private MockHelper mockHelper;

    @Before
    public void Before() {
        MockitoAnnotations.initMocks(this);
        mockHelper = TestHelpers.getMockHelper();
    }

    @Test
    public void testSamlTokenGeneration() throws Exception {

//        mockHelper.getClientAttributes().put(WSFedSAML11AssertionTypeBuilder, "false");
        mockHelper.getClientSessionNotes().put(GeneralConstants.NAMEID_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED.get());

        //Role Mapper
        ProtocolMapperModel roleMappingModel = mock(ProtocolMapperModel.class);
        when(roleMappingModel.getProtocolMapper()).thenReturn(UUID.randomUUID().toString());
        WSFedSAMLRoleListMapper roleListMapper = mock(WSFedSAMLRoleListMapper.class);
        mockHelper.getProtocolMappers().put(roleMappingModel, roleListMapper);

        //Attribute Mapper
        ProtocolMapperModel attributeMappingModel = mock(ProtocolMapperModel.class);
        when(attributeMappingModel.getProtocolMapper()).thenReturn(UUID.randomUUID().toString());
        WSFedSAMLAttributeStatementMapper attributeMapper = mock(WSFedSAMLAttributeStatementMapper.class);
        mockHelper.getProtocolMappers().put(attributeMappingModel, attributeMapper);


        mockHelper.initializeMockValues();

        //SAML Token generation
        WsFedSAML11AssertionTypeBuilder samlBuilder = new WsFedSAML11AssertionTypeBuilder();
        samlBuilder.setRealm(mockHelper.getRealm())
                .setUriInfo(mockHelper.getUriInfo())
                .setAccessCode(mockHelper.getAccessCode())
                .setClientSession(mockHelper.getClientSessionModel())
                .setUserSession(mockHelper.getUserSessionModel())
                .setSession(mockHelper.getSession());

        SAML11AssertionType token = samlBuilder.build();

        assertNotNull(token);

        assertEquals(String.format("%s/realms/%s", mockHelper.getBaseUri(), mockHelper.getRealmName()), token.getIssuer());
        // TODO fix me! Check the specs if the name id format is a part of the SAML 1.1 token
//        assertEquals(URI.create(mockHelper.getClientSessionNotes().get(WSFED_NAME_ID_FORMAT)), JBossSAMLURIConstants.NAMEID_FORMAT_UNSPECIFIED);
//         TODO: fix me!
        //assertEquals(mockHelper.getEmail(), token.);

        assertNotNull(token.getIssueInstant());
        assertNotNull(token.getConditions().getNotBefore());
        assertNotNull(token.getConditions().getNotOnOrAfter());

        assertNotNull(token.getStatements());
        assertNotNull(token.getConditions().getNotOnOrAfter());

        // Verify that the token time is within the time interval specified by the conditions statement
        // and that the time interval is adjusted by a small amount to account for clock skew
        assertEquals(token.getConditions().getNotBefore(), XMLTimeUtil.subtract(token.getIssueInstant(), CLOCK_SKEW));
        assertEquals(XMLTimeUtil.add(token.getConditions().getNotBefore(), mockHelper.getAccessCodeLifespan() * 1000 + CLOCK_SKEW + CLOCK_SKEW), token.getConditions().getNotOnOrAfter());
        assertEquals(XMLTimeUtil.add(token.getIssueInstant(), mockHelper.getAccessCodeLifespan() * 1000 + CLOCK_SKEW), token.getConditions().getNotOnOrAfter());

        assertEquals(mockHelper.getClientId(), ((SAML11AudienceRestrictionCondition) token.getConditions().get().get(0)).get().get(0).toString());

        assertTrue(token.getStatements().size() > 1);
        assertNotNull(token.getStatements().get(1));
        assertTrue(token.getStatements().get(1) instanceof SAML11AuthenticationStatementType);

        SAML11AuthenticationStatementType authType = (SAML11AuthenticationStatementType)token.getStatements().get(1);
        assertEquals(authType.getAuthenticationInstant(), token.getIssueInstant());
        assertEquals(authType.getAuthenticationMethod().toString(), JBossSAMLURIConstants.AC_PASSWORD_PROTECTED_TRANSPORT.get());
        assertEquals(authType.getSubject().getSubjectConfirmation().getConfirmationMethod().get(0), URI.create("urn:oasis:names:tc:SAML:1.0:cm:bearer"));

        ClientSessionModel clientSession = mockHelper.getClientSessionModel();
        verify(clientSession, times(1)).setNote(WsFedSAML11AssertionTypeBuilder.WSFED_NAME_ID, mockHelper.getUserName());
        verify(clientSession, times(1)).setNote(WSFED_NAME_ID_FORMAT, mockHelper.getClientSessionNotes().get(GeneralConstants.NAMEID_FORMAT));

        verify(roleListMapper, times(1)).mapRoles(any(AttributeStatementType.class), eq(roleMappingModel), eq(mockHelper.getSession()), eq(mockHelper.getUserSessionModel()), eq(mockHelper.getClientSessionModel()));
        verify(attributeMapper, times(1)).transformAttributeStatement(any(AttributeStatementType.class), eq(attributeMappingModel), eq(mockHelper.getSession()), eq(mockHelper.getUserSessionModel()), eq(mockHelper.getClientSessionModel()));

    }
}
