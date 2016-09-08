# UserInfo claim Attribute Importer

Imports claims from a set of claims returned by the OpenID Connect external identity provider's /userinfo endpoint.

## Install 

The simpliest way to deploy the new attribute importer is to build the keycloak and copy examples\providers\userinfo-attribute-mapper\target\userinfo-attribute-mapper.jar 
to $KEYCLOAK_ROOTDIR/providers directory:

---
$ mvn install -Pdistribution
$ cp examples/providers/userinfo-attribute-mapper/target/user-info-attribute-mapper.jar $KEYCLOAK_ROOTDIR/providers
---

