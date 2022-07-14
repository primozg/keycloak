/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.storage.ldap.mappers.ppolicy;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.CredentialValidationOutput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProviderFactory;
import org.keycloak.storage.ldap.idm.store.ldap.LDAPIdentityStore;

/**
 *
 * @author Uporabnik
 */
public class PPolicyLDAPStorageProvider extends LDAPStorageProvider{
    
    public PPolicyLDAPStorageProvider(LDAPStorageProviderFactory factory, KeycloakSession session, ComponentModel model, LDAPIdentityStore ldapIdentityStore) {
        super(factory, session, model, ldapIdentityStore);
    }
   /*     public PPolicyLDAPStorageProvider(LDAPStorageProvider ldapsp) {
        super(ldapsp);
    }
*/
    @Override
    public CredentialValidationOutput authenticate(RealmModel realm, CredentialInput cred) {
        return super.authenticate(realm, cred); //To change body of generated methods, choose Tools | Templates.
    }
        
}
