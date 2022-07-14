/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

org.keycloak.storage.ldap.mappers.ppolicy.PPolicyUserAccountControlStorageMapperFactory
 */

package org.keycloak.storage.ldap.mappers.ppolicy;

import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPConfig;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapperFactory;
import org.keycloak.storage.ldap.mappers.FullNameLDAPStorageMapper;

import java.util.ArrayList;
import java.util.List;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PPolicyUserAccountControlStorageMapperFactory extends AbstractLDAPStorageMapperFactory {

    public static final String PROVIDER_ID = "ldap-ppolicy-attribute-mapper";
    protected static final List<ProviderConfigProperty> configProperties;

    static {
        configProperties = getConfigProps(null);
    }

    private static List<ProviderConfigProperty> getConfigProps(ComponentModel parent) {
        return ProviderConfigurationBuilder.create()
         /*      .property().name(PPolicyUserAccountControlStorageMapper.LDAP_PASSWORD_POLICY_HINTS_ENABLED)
                .label("Password Policy Hints Enabled")
                .helpText("Applicable just for writable MSAD. If on, then updating password of MSAD user will use LDAP_SERVER_POLICY_HINTS_OID " +
                        "extension, which means that advanced MSAD password policies like 'password history' or 'minimal password age' will be applied. This extension works just for MSAD 2008 R2 or newer.")
                .type(ProviderConfigProperty.BOOLEAN_TYPE)
                .defaultValue("false")
                .add()*/
                .property().name(OpenLDAPConstants.LOGINSHELL)
                .label("Default login shell")
                .helpText("Used only for posixAccount objectClass")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("/bin/bash")
                .add()
                .property().name(OpenLDAPConstants.GIDNUMBER)
                .label("Default groupID")
                .helpText("Used only for posixAccount objectClass")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("10001")
                .add()
                .property().name(OpenLDAPConstants.HOMEDIRECTORY)
                .label("Default home directory prefix")
                .helpText("Used only for posixAccount objectClass")
                .type(ProviderConfigProperty.STRING_TYPE)
                .defaultValue("/home/")
                .add()
                .build();

    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) throws ComponentValidationException {

        String test = config.getConfig().getFirst(OpenLDAPConstants.LOGINSHELL);
        if (test == null) {
            throw new ComponentValidationException(OpenLDAPConstants.LOGINSHELL+" not set");
        }
        test = config.getConfig().getFirst(OpenLDAPConstants.HOMEDIRECTORY);
        if (test == null) {
            throw new ComponentValidationException(OpenLDAPConstants.HOMEDIRECTORY+" not set");
        }
        test = config.getConfig().getFirst(OpenLDAPConstants.GIDNUMBER);
        if (test == null) {
            throw new ComponentValidationException(OpenLDAPConstants.GIDNUMBER+" not set");
        }
         try{
             Integer.parseInt(test);
        }catch(Exception e){
            throw new ComponentValidationException(OpenLDAPConstants.GIDNUMBER+" not a number");
        }     
    }
    
    
    @Override
    public String getHelpText() {
        return "Mapper specific to MSAD. It's able to integrate the MSAD user account state into Keycloak account state (account enabled, password is expired etc). It's using userAccountControl and pwdLastSet MSAD attributes for that. " +
                "For example if pwdLastSet is 0, the Keycloak user is required to update password, if userAccountControl is 514 (disabled account) the Keycloak user is disabled as well etc. Mapper is also able to handle exception code from LDAP user authentication.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties(RealmModel realm, ComponentModel parent) {
        return getConfigProps(parent);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected AbstractLDAPStorageMapper createMapper(ComponentModel mapperModel, LDAPStorageProvider federationProvider) {
        return new PPolicyUserAccountControlStorageMapper(mapperModel, federationProvider);
    }
}
