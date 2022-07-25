/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.gorkic.keycloak.auth;


import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.*;
import org.keycloak.events.Errors;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;


/**
 *
 * @author primo
 */
 
public class PasswordCheck implements Authenticator, AuthenticatorFactory {

    private static final Logger logger = Logger.getLogger(PasswordCheck.class);

    public static final String PROVIDER_ID = "old-password-check";
    public static final String CLIENTID="account-console";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
          logger.error("Old password check authenticate void");
        
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String pwd = formData.getFirst(CredentialRepresentation.PASSWORD);
        String clientid = context.getAuthenticationSession().getClient().getClientId();//contextformData.getFirst("client_id");
        
      if(!clientid.equals(CLIENTID)){
       boolean valid = context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(), UserCredentialModel.password(pwd));
  
        if (!valid) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return;
        }
       
      }
       
      //context.attempted();
       
    }
    

    @Override
    public boolean requiresUser() {
         logger.error("requiresUser");
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public String getDisplayType() {
        return "Validate Current Password";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Validate old password for console";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void close() {

    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
       logger.error("Old password check action void");
       context.success();
    }
}
