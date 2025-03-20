package com.agronod.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;

import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by joris on 11/11/2016.
 */
public class KeycloakEmailAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "email-authentication";

    private static Logger logger = Logger.getLogger(KeycloakEmailAuthenticatorFactory.class);
    private static final KeycloakEmailAuthenticator SINGLETON = new KeycloakEmailAuthenticator();

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES =
            {AuthenticationExecutionModel.Requirement.REQUIRED,
                    AuthenticationExecutionModel.Requirement.ALTERNATIVE,
                    AuthenticationExecutionModel.Requirement.DISABLED};

    private static final List<ProviderConfigProperty> configProperties =
            new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(EmailAuthenticatorContstants.CODE_VALIDINMIN);
        property.setLabel("Email Code Validity (minutes)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("5"); // Set default to 5 minutes
        property.setHelpText("The validity period of the email code in minutes.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(EmailAuthenticatorContstants.CODE_ACTIVATIONDELAYINSEC);
        property.setLabel("Activation Delay (seconds)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("2"); // Set default to 2 seconds
        property.setHelpText("Delay in seconds before the email code becomes active.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(EmailAuthenticatorContstants.API_URL);
        property.setLabel("API URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("The URL of the API to send the email code.");
        configProperties.add(property);
    }

    public String getId() {
        logger.debug("getId called ... returning " + PROVIDER_ID);
        return PROVIDER_ID;
    }

    public Authenticator create(KeycloakSession session) {
        logger.debug("create called ... returning " + SINGLETON);
        return SINGLETON;
    }

    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        logger.debug("getRequirementChoices called ... returning " + REQUIREMENT_CHOICES);
        return REQUIREMENT_CHOICES;
    }

    public boolean isUserSetupAllowed() {
        logger.debug("isUserSetupAllowed called ... returning true");
        return true;
    }

    public boolean isConfigurable() {
        boolean result = true;
        logger.debug("isConfigurable called ... returning " + result);
        return result;
    }

    public String getHelpText() {
        logger.debug("getHelpText called ...");
        return "Validates an OTP sent by EMAIL.";
    }

    public String getDisplayType() {
        String result = "Email Authentication";
        logger.debug("getDisplayType called ... returning " + result);
        return result;
    }

    public String getReferenceCategory() {
        logger.debug("getReferenceCategory called ... returning email-auth-code");
        return "email-auth-code";
    }

    public List<ProviderConfigProperty> getConfigProperties() {
        logger.debug("getConfigProperties called ... returning " + configProperties);
        return configProperties;
    }

    public void init(Config.Scope config) {
        logger.debug("init called ... config.scope = " + config);
    }

    public void postInit(KeycloakSessionFactory factory) {
        logger.debug("postInit called ... factory = " + factory);
    }

    public void close() {
        logger.debug("close called ...");
    }
}
