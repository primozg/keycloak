package com.gorkic.keycloak.auth;

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
import org.jboss.logging.Logger;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.Constants;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.requiredactions.UpdatePassword;

/**
 * @author <a href="mailto:bill@burkecentral.com">Primoz Gorkic at
 * gorkic.com</a>
 * @version $Revision: 1 $
 */
public class UpdatePasswordWithOld extends UpdatePassword {

    private static final Logger logger = Logger.getLogger(UpdatePasswordWithOld.class);
    public static final String PASSWORD_CURRENT_FIELD = "password-current";  
    public static final String USERNAME = "username";

    @Override
    public void processAction(RequiredActionContext context) {
        logger.debug("Custom password check processAction");
        EventBuilder event = context.getEvent();
        AuthenticationSessionModel authSession = context.getAuthenticationSession();

        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        event.event(EventType.RESET_PASSWORD);
        String password = formData.getFirst(PASSWORD_CURRENT_FIELD);

        if (authSession != null && authSession.getClientNote(Constants.KC_ACTION_EXECUTING) != null) {

            boolean valid = context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(), UserCredentialModel.password(password));
            if (!valid) {
                EventBuilder errorEvent = context.getEvent().clone().event(EventType.UPDATE_PASSWORD_ERROR)
                        .client(authSession.getClient())
                        .user(authSession.getAuthenticatedUser());
                Response challenge = context.form()
                        .setAttribute(USERNAME, authSession.getAuthenticatedUser().getUsername())
                        .addError(new FormMessage(PASSWORD_CURRENT_FIELD, Messages.INVALID_PASSWORD))
                        .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
                errorEvent.error(Errors.PASSWORD_MISSING);
                return;
            }
        }

        super.processAction(context);

    }

    @Override
    public String getDisplayText() {
        return "Update Password OWASP";
    }

}
