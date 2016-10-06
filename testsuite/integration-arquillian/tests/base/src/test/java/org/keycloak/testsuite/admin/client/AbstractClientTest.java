/*
 * Copyright 2016 Red Hat Inc. and/or its affiliates and other contributors
 * as indicated by the @author tags. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package org.keycloak.testsuite.admin.client;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testsuite.AbstractAuthTest;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.events.EventsListenerProviderFactory;
import org.keycloak.testsuite.util.AdminEventPaths;
import org.keycloak.testsuite.util.AssertAdminEvents;
import org.keycloak.testsuite.util.RealmBuilder;

import javax.ws.rs.core.Response;
import java.util.List;

/**
 *
 * @author Stan Silvert ssilvert@redhat.com (C) 2016 Red Hat Inc.
 */
public abstract class AbstractClientTest extends AbstractAuthTest {

    @Rule
    public AssertAdminEvents assertAdminEvents = new AssertAdminEvents(this);

    @Before
    public void setupAdminEvents() {
        RealmRepresentation realm = testRealmResource().toRepresentation();
        if (realm.getEventsListeners() == null || !realm.getEventsListeners().contains(EventsListenerProviderFactory.PROVIDER_ID)) {
            realm = RealmBuilder.edit(testRealmResource().toRepresentation()).testEventListener().build();
            testRealmResource().update(realm);
        }
    }

    @After
    public void tearDownAdminEvents() {
        RealmRepresentation realm = RealmBuilder.edit(testRealmResource().toRepresentation()).removeTestEventListener().build();
        testRealmResource().update(realm);
    }

    protected RealmRepresentation realmRep() {
        return testRealmResource().toRepresentation();
    }

    protected String getRealmId() {
        return "master";
    }

    // returns UserRepresentation retrieved from server, with all fields, including id
    protected UserRepresentation getFullUserRep(String userName) {
        List<UserRepresentation> results = testRealmResource().users().search(userName, null, null, null, null, null);
        if (results.size() != 1) throw new RuntimeException("Did not find single user with username " + userName);
        return results.get(0);
    }

    protected String createOidcClient(String name) {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(name);
        clientRep.setName(name);
        clientRep.setRootUrl("foo");
        clientRep.setProtocol("openid-connect");
        return createClient(clientRep);
    }

    protected String createSamlClient(String name) {
        ClientRepresentation clientRep = new ClientRepresentation();
        clientRep.setClientId(name);
        clientRep.setName(name);
        clientRep.setProtocol("saml");
        clientRep.setAdminUrl("samlEndpoint");
        return createClient(clientRep);
    }

    protected String createClient(ClientRepresentation clientRep) {
        Response resp = testRealmResource().clients().create(clientRep);
        resp.close();
        String id = ApiUtil.getCreatedId(resp);

        assertAdminEvents.assertEvent(getRealmId(), OperationType.CREATE, AdminEventPaths.clientResourcePath(id), clientRep, ResourceType.CLIENT);

        return id;
    }

    protected void removeClient(String clientDbId) {
        testRealmResource().clients().get(clientDbId).remove();

        assertAdminEvents.assertEvent(getRealmId(), OperationType.DELETE, AdminEventPaths.clientResourcePath(clientDbId), ResourceType.CLIENT);
    }

    protected ClientRepresentation findClientRepresentation(String name) {
        ClientResource clientRsc = findClientResource(name);
        if (clientRsc == null) return null;
        return findClientResource(name).toRepresentation();
    }

    protected ClientResource findClientResource(String name) {
        return ApiUtil.findClientResourceByName(testRealmResource(), name);
    }

    protected ClientResource findClientResourceById(String id) {
        return ApiUtil.findClientResourceByClientId(testRealmResource(), id);
    }

}
