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
 */
package org.keycloak.storage.ldap.mappers.ppolicy;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.LDAPConstants;
import org.keycloak.models.ModelException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.ldap.LDAPStorageProvider;
import org.keycloak.storage.ldap.idm.model.LDAPObject;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.storage.ldap.mappers.AbstractLDAPStorageMapper;
import org.keycloak.storage.ldap.mappers.LDAPOperationDecorator;
import org.keycloak.storage.ldap.mappers.PasswordUpdateCallback;
import org.keycloak.storage.ldap.mappers.TxAwareLDAPUserModelDelegate;

import javax.naming.AuthenticationException;
import java.util.Objects;
import static java.util.Objects.isNull;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.keycloak.storage.ldap.LDAPUtils;
import org.keycloak.storage.ldap.idm.query.Condition;
import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;
import org.keycloak.storage.ldap.mappers.LDAPMappersComparator;
import org.keycloak.storage.user.SynchronizationResult;

/**
 * Mapper specific to MSAD. It's able to read the userAccountControl and
 * pwdLastSet attributes and set actions in Keycloak based on that. It's also
 * able to handle exception code from LDAP user authentication (See
 * http://www-01.ibm.com/support/docview.wss?uid=swg21290631 )
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PPolicyUserAccountControlStorageMapper extends AbstractLDAPStorageMapper implements PasswordUpdateCallback {

    protected String homedirectory;
    protected String gidnumber;
    protected String loginshell;
    //public static final String LDAP_LOCKED_TIME = "pwdAccountLockedTime";
    public static final String LDAP_PASSWORD_POLICY_HINTS_ENABLED = "ldap.password.policy.hints.enabled";

    private static final Logger logger = Logger.getLogger(PPolicyUserAccountControlStorageMapper.class);

    //  private static final Pattern AUTH_EXCEPTION_REGEX = Pattern.compile(".*AcceptSecurityContext error, data ([0-9a-f]*), v.*");
    private static final Pattern AUTH_INVALID_NEW_PASSWORD = Pattern.compile(".*ERROR CODE ([0-9A-F]+) - ([0-9A-F]+): .*WILL_NOT_PERFORM.*");

    public PPolicyUserAccountControlStorageMapper(ComponentModel mapperModel, LDAPStorageProvider ldapProvider) {
        super(mapperModel, ldapProvider);
        ldapProvider.setUpdater(this);
        this.homedirectory = mapperModel.getConfig().getFirst(OpenLDAPConstants.HOMEDIRECTORY);
        this.gidnumber = mapperModel.getConfig().getFirst(OpenLDAPConstants.GIDNUMBER);
        this.loginshell = mapperModel.getConfig().getFirst(OpenLDAPConstants.LOGINSHELL);
        //  logger.info("PPolicyUserAccountControlStorageMapper init");
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        // logger.info("beforeLDAPQuery");
        //   query.addReturningLdapAttribute(OpenLDAPConstants.PWDCHANGEDTIME);
        //  query.addReturningLdapAttribute(OpenLDAPConstants.USERCONTROL);
        // query.addReturningReadOnlyLdapAttribute("memberOf");
        //query.addReturningLdapAttribute("+");
        // This needs to be read-only and can be set to writable just on demand
        query.addReturningReadOnlyLdapAttribute(OpenLDAPConstants.PWDCHANGEDTIME);
        //  query.addReturningReadOnlyLdapAttribute(OpenLDAPConstants.PWDCHANGEDTIME);
        query.addReturningLdapAttribute(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME);
        query.addReturningLdapAttribute(OpenLDAPConstants.PWDRESET);
        //  query.addReturningLdapAttribute(OpenLDAPConstants.USERCONTROL);
        /*      */
 /*    if (ldapProvider.getEditMode() != UserStorageProvider.EditMode.WRITABLE) {
            query.addReturningReadOnlyLdapAttribute(OpenLDAPConstants.USERCONTROL);
        }
         */
    }

    @Override
    public SynchronizationResult syncDataFromKeycloakToFederationProvider(RealmModel realm) {

        return super.syncDataFromKeycloakToFederationProvider(realm); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SynchronizationResult syncDataFromFederationProviderToKeycloak(RealmModel realm) {
        return super.syncDataFromFederationProviderToKeycloak(realm); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public LDAPOperationDecorator beforePasswordUpdate(UserModel user, LDAPObject ldapUser, UserCredentialModel password) {
        logger.info("beforePasswordUpdate:" + ldapUser.getDn());
        // Not apply policies if password is reset by admin (not by user himself)
        if (password.isAdminRequest()) {
            return null;
        }

        boolean applyDecorator = mapperModel.get(LDAP_PASSWORD_POLICY_HINTS_ENABLED, false);
        return applyDecorator ? new LDAPServerPolicyHintsDecorator() : null;
    }

    @Override
    public void passwordUpdated(UserModel user, LDAPObject ldapUser, UserCredentialModel password) {
        logger.info("Going to update userAccountControl for ldap user '%s' after successful password update " + ldapUser.getDn().toString());

        // Normally it's read-only
        //  ldapUser.removeReadOnlyAttributeName(OpenLDAPConstants.PWDRESET);
        ldapUser.setAttribute(OpenLDAPConstants.PWDRESET, new HashSet<String>());
        //   ldapUser.setSingleAttribute(LDAPConstants.PWD_LAST_SET, "-1");

        //    PPolicyControl control = getUserAccountControl(ldapUser);
        //    control.remove(UserAccountControl.PASSWD_NOTREQD);
        //    control.remove(UserAccountControl.PASSWORD_EXPIRED);
        if (user.isEnabled()) {
            //   control.remove(UserAccountControl.ACCOUNTDISABLE);
            ldapUser.setAttribute(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME, new HashSet<String>());

        }
        ldapProvider.getLdapIdentityStore().update(ldapUser);
        //  updateUserAccountControl(true, ldapUser);
    }

    @Override
    public void passwordUpdateFailed(UserModel user, LDAPObject ldapUser, UserCredentialModel password, ModelException exception) {
        throw processFailedPasswordUpdateException(exception);
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate, RealmModel realm) {
        // logger.info("proxy UserModel");
        return new PPolicyUserModelDelegate(delegate, ldapUser);
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser, RealmModel realm) {
        
        if (ldapUser.getObjectClasses().contains("posixAccount")) {
            logger.info("onRegisterUserToLDAP ADDING posixAccount defaults");
//var userStorage = StorageManager.getStorageProvider(keycloakSession, realm, PROVIDER_ID);
//LDAPQuery    ldapQuery = LDAPUtils.c.createQueryForUserSearch(realm.getu., realm);
            LDAPQuery query = LDAPUtils.createQueryForUserSearch(ldapProvider, realm);
            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();
            Condition userDNCondition = conditionsBuilder.addCustomLDAPFilter("(&(|(objectclass=inetOrgPerson)(objectclass=organizationalPerson))(uidNumber=*))");
            query.addWhereCondition(userDNCondition);
            query.addReturningLdapAttribute("uidNumber");
            //  query.addReturningLdapAttribute("gidNumber");
            //  LDAPMappersComparator  ldapMappersComparator = new LDAPMappersComparator();
            //    LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();

            //    Condition attrCondition = conditionsBuilder.addCustomLDAPFilter("uidNumber=*");
            //     query.addWhereCondition(attrCondition);
            //query.sortBy(conditionsBuilder.desc("uidNumber"));
            // query.setLimit(1);
            List<LDAPObject> users = ldapProvider.getLdapIdentityStore().fetchQueryResults(query);
//.searchForUser("", realm);//.searchForUserByUserAttribute("uidNumber","%", realm);
            Set<Integer> uidNumbers = new HashSet();
            String max = null;
            //  String gid = null;
            for (LDAPObject u : users) {
                max = u.getAttributeAsString("uidNumber");
                //    gid = u.getAttributeAsString("gidNumber");
                uidNumbers.add(Integer.parseInt(max));
                //  logger.info("uidNumber najdel "+u.getAttributeAsString(max));

            }
            Integer maxid = Collections.max(uidNumbers) + 1;
            String home = homedirectory.concat(localUser.getUsername());
            //    Set<String> uid=new HashSet(){};
            //    uid.add(max.toString());
            //  ldapUser.setAttribute("uidNumber", (Set) Collections.singleton(max.toString()));
            /*    List<String> a=new ArrayList();
      a.add(maxid.toString());
      List<String> b=new ArrayList();
      b.add(home);      */
            // ldapUser.setAttribute("uidNumber", (Set) Collections.singleton(maxid));
            ldapUser.setSingleAttribute(OpenLDAPConstants.UIDNUMBER, maxid.toString());
            ldapUser.setSingleAttribute(OpenLDAPConstants.GIDNUMBER, gidnumber);
            ldapUser.setSingleAttribute(OpenLDAPConstants.HOMEDIRECTORY, home);
            ldapUser.setSingleAttribute(OpenLDAPConstants.LOGINSHELL, loginshell);
            localUser.setSingleAttribute(OpenLDAPConstants.UIDNUMBER, maxid.toString());
            localUser.setSingleAttribute(OpenLDAPConstants.GIDNUMBER, gidnumber);
            //     localUser.setAttribute("uidNumber",Arrays.asList(Collections.singleton(max.toString())));
            localUser.setSingleAttribute(OpenLDAPConstants.HOMEDIRECTORY, home);
            localUser.setSingleAttribute(OpenLDAPConstants.LOGINSHELL, loginshell);
            //  super.onRegisterUserToLDAP( ldapUser,  localUser,  realm);
            /**/
        }
    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, RealmModel realm, boolean isCreate) {
        // logger.info("onImportUserFromLDAP: " + user.getUsername());
        boolean locked = isNull(ldapUser.getAttributeAsString(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME));
        boolean reset = isNull(ldapUser.getAttributeAsString(OpenLDAPConstants.PWDRESET));
        if (reset) {
            user.removeRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        } else {
            //   logger.info("onImportUserFromLDAP adding pwdReset for " + user.getUsername());
            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }

        user.setEnabled(locked);

    }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException, RealmModel realm) {
        logger.info("onAuthenticationFailure:" + ldapException.getMessage());
        //    String locked=ldapUser.getAttributeAsString(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME);
        //   String ldap=ldapProvider.getLdapIdentityStore().getConfig().getConnectionUrl();

        //  logger.error("onAuthenticationFailure 2:",ldapException.getSuppressed());
        // logger.info("Enabled:"+ user.isEnabled());
        // logger.info("PWDACCOUNTLOCKEDTIME:"+locked);
        //if (user.isEnabled()){
        return false;
        //}else{
        //return true;
        //}
        //logger.error("STACK:",ldapException.fillInStackTrace());
        /*
        String exceptionMessage = ldapException.getMessage();
        Matcher m = AUTH_EXCEPTION_REGEX.matcher(exceptionMessage);
        logger.error("onAuthenticationFailureCode:"+exceptionMessage);
        if (m.matches()) {
            String errorCode = m.group(1);
            return processAuthErrorCode(errorCode, user);
        } else {
            return false;
        }
         */

    }

    protected boolean processAuthErrorCode(String errorCode, UserModel user) {
        logger.debugf("MSAD Error code is '%s' after failed LDAP login of user '%s'", errorCode, user.getUsername());

        if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
            if (errorCode.equals("532") || errorCode.equals("773")) {
                // User needs to change his MSAD password. Allow him to login, but add UPDATE_PASSWORD required action
                if (user.getRequiredActionsStream().noneMatch(action -> Objects.equals(action, UserModel.RequiredAction.UPDATE_PASSWORD.name()))) {
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                }
                return true;
            } else if (errorCode.equals("533")) {
                // User is disabled in MSAD. Set him to disabled in KC as well
                if (user.isEnabled()) {
                    user.setEnabled(false);
                }
                return true;
            } else if (errorCode.equals("775")) {
                logger.warnf("Locked user '%s' attempt to login", user.getUsername());
            }
        }

        return false;
    }

    protected ModelException processFailedPasswordUpdateException(ModelException e) {
        logger.info("processFailedPasswordUpdateException:" + e.getMessage());
        if (e.getCause() == null || e.getCause().getMessage() == null) {
            return e;
        }

        String exceptionMessage = e.getCause().getMessage().replace('\n', ' ');
        logger.debugf("Failed to update password in Active Directory. Exception message: %s", exceptionMessage);
        exceptionMessage = exceptionMessage.toUpperCase();

        Matcher m = AUTH_INVALID_NEW_PASSWORD.matcher(exceptionMessage);
        if (m.matches()) {
            String errorCode = m.group(1);
            String errorCode2 = m.group(2);

            // 52D corresponds to ERROR_PASSWORD_RESTRICTION. See https://msdn.microsoft.com/en-us/library/windows/desktop/ms681385(v=vs.85).aspx
            if ((errorCode.equals("53")) && errorCode2.endsWith("52D")) {
                ModelException me = new ModelException("invalidPasswordGenericMessage", e);
                return me;
            }
        }

        return e;
    }

    protected PPolicyControl getUserAccountControl(LDAPObject ldapUser) {
        //  logger.info("User control: " + LDAPConstants.USER_ACCOUNT_CONTROL);
        /*  String userAccountControl = ldapUser.getAttributeAsString(OpenLDAPConstants.USERCONTROL);
        long longValue = userAccountControl == null ? 0 : Long.parseLong(userAccountControl);
        return new UserAccountControl(longValue);*/
        return new PPolicyControl();
    }

    // Update user in LDAP if "updateInLDAP" is true. Otherwise it is assumed that LDAP update will be called at the end of transaction
    /*   protected void updateUserAccountControl(boolean updateInLDAP, LDAPObject ldapUser) {
        logger.info("updateUserAccountControl: " + ldapUser.getDn().toString());
     //   String userAccountControlValue = String.valueOf(accountControl.getValue());
    //    logger.infof("Updating userAccountControl of user '%s' to value '%s'", ldapUser.getDn().toString(), userAccountControlValue);
//logger.infof("Updating userAccountControl of user '%s' to value '%s'", ldapUser.getDn().toString(),"locked");
     
   // ldapUser.setSingleAttribute(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME,OpenLDAPConstants.LOCKED);

     if (updateInLDAP) {
            ldapProvider.getLdapIdentityStore().update(ldapUser);
        }
    }
     */
    public class PPolicyUserModelDelegate extends TxAwareLDAPUserModelDelegate {

        private final LDAPObject ldapUser;

        public PPolicyUserModelDelegate(UserModel delegate, LDAPObject ldapUser) {

            super(delegate, ldapProvider, ldapUser);
            this.ldapUser = ldapUser;
            //   logger.info("PPolicyUserModelDelegate");
        }

        @Override
        public boolean isEnabled() {
            boolean enabled;

            //  boolean kcEnabled = super.isEnabled();
            // izpisLdap();
            //    if (getPwdLastSet() > 0) {                  
            boolean ldapEnabled = isNull(ldapUser.getAttributeAsString(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME));
            //         logger.info("ldapEnabled:"+ldapEnabled); 
            /*      if(kcEnabled!=ldapEnabled){
                      super.setEnabled(ldapEnabled);
                  }*/
            // Merge KC and MSAD
            //  return kcEnabled && !getUserAccountControl(ldapUser).has(UserAccountControl.ACCOUNTDISABLE);
            enabled = ldapEnabled;
            /*      } else {
                logger.info("kcEnabled:"+kcEnabled);
                // If new MSAD user is created and pwdLastSet is still 0, MSAD account is in disabled state. So read just from Keycloak DB. User is not able to login via MSAD anyway
                enabled=kcEnabled;
            }*/
            //   logger.info("isEnabled: "+enabled);
            return enabled;

        }

        @Override
        public void setEnabled(boolean enabled) {
            //    logger.info("setEnabled: " + enabled);
            // Always update DB
            super.setEnabled(enabled);

            //    PPolicyControl control = getUserAccountControl(ldapUser);
            if (enabled) {
                //        ldapUser.removeReadOnlyAttributeName(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME);
                ldapUser.setAttribute(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME, new HashSet<String>());
                //    control.remove(UserAccountControl.ACCOUNTDISABLE);
            } else {
                //  ldapUser.addReadOnlyAttributeName(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME);
                ldapUser.setSingleAttribute(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME, OpenLDAPConstants.LOCKED);
                //,"20210128174138.892Z");
                //   control.add(UserAccountControl.ACCOUNTDISABLE);
            }
            //    logger.info("setEnabled update user in LDAP");
            // ldapProvider.getLdapIdentityStore().update(ldapUser);
            //markUpdatedAttributeInTransaction(OpenLDAPConstants.PWDACCOUNTLOCKEDTIME);

            //    markUpdatedAttributeInTransaction(UserModel.ENABLED);
            ldapProvider.getLdapIdentityStore().update(ldapUser);
            // ldapProvider.getLdapIdentityStore().update(ldapUser);
            //  updateUserAccountControl(false, ldapUser);
            //  }
        }

        @Override
        public void addRequiredAction(RequiredAction action) {

            String actionName = action.name();
            addRequiredAction(actionName);
        }

        @Override
        public void addRequiredAction(String action) {
            //  logger.info("addRequiredAction:" + action);
            // Always update DB
            super.addRequiredAction(action);

            if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE && RequiredAction.UPDATE_PASSWORD.toString().equals(action)) {
                //    logger.debugf("Going to propagate required action UPDATE_PASSWORD to MSAD for ldap user '%s' ", ldapUser.getDn().toString());

                // Normally it's read-only
                //ldapUser.removeReadOnlyAttributeName(OpenLDAPConstants.PWDCHANGEDTIME);
                ldapUser.setSingleAttribute(OpenLDAPConstants.PWDRESET, "TRUE");
                ldapProvider.getLdapIdentityStore().update(ldapUser);
                markUpdatedRequiredActionInTransaction(action);
            }
        }

        @Override
        public void removeRequiredAction(RequiredAction action) {
            String actionName = action.name();
            removeRequiredAction(actionName);
        }

        @Override
        public void removeRequiredAction(String action) {
            // Always update DB
            //    logger.info("removeRequiredAction:" + action);
            super.removeRequiredAction(action);

            if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE && RequiredAction.UPDATE_PASSWORD.toString().equals(action)) {

                // Don't set pwdLastSet in MSAD when it is new user
//                PPolicyControl accountControl = getUserAccountControl(ldapUser);
                //  if (accountControl.getValue() != 0 && !accountControl.has(UserAccountControl.PASSWD_NOTREQD)) {
                //         logger.debugf("Going to remove required action UPDATE_PASSWORD from MSAD for ldap user '%s' ", ldapUser.getDn().toString());
                //  logger.info("removeRequiredAction getEditMode");
                // Normally it's read-only
                ldapUser.setAttribute(OpenLDAPConstants.PWDRESET, new HashSet<String>());
                ldapProvider.getLdapIdentityStore().update(ldapUser);
                //   ldapUser.setSingleAttribute(OpenLDAPConstants.PWDCHANGEDTIME, "-1");

                markUpdatedRequiredActionInTransaction(action);
                //  }
            }
            //  logger.info("removeRequiredAction end");
        }

        @Override
        public Stream<String> getRequiredActionsStream() {
            logger.info("getRequiredActionsStream");
            if (ldapProvider.getEditMode() == UserStorageProvider.EditMode.WRITABLE) {
                /*    if (getPwdLastSet() == 0 || getUserAccountControl(ldapUser).has(UserAccountControl.PASSWORD_EXPIRED)) {
                    return Stream.concat(super.getRequiredActionsStream(), Stream.of(RequiredAction.UPDATE_PASSWORD.toString()))
                            .distinct();
                }*/
            }
            return super.getRequiredActionsStream();
        }

        protected void izpisLdap() {
            for (String ime : ldapUser.getReadOnlyAttributeNames()) {
                logger.info("Read-Only: " + ime);
            }

            Map<String, Set<String>> m = ldapUser.getAttributes();
            for (Map.Entry<String, Set<String>> entry : m.entrySet()) {
                logger.info("Atribut: " + entry.getKey() + " " + entry.getValue());
            }

        }

        protected long getPwdLastSet() {

            String pwdLastSet = ldapUser.getAttributeAsString(OpenLDAPConstants.PWDCHANGEDTIME);
            Date pwdlast = parseLdapDate(pwdLastSet);
            logger.info("getPwdLastSet: " + pwdLastSet);
            return pwdLastSet == null ? 0 : pwdlast.getTime();
        }

        public Date parseLdapDate(String ldapDate) {
            if (isNull(ldapDate)) {
                return null;
            }
            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            sdf.setTimeZone(TimeZone.getTimeZone("GMT"));

            try {
                return sdf.parse(ldapDate);
            } catch (ParseException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return null;
        }

    }

}
