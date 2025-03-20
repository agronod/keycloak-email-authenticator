package com.agronod.keycloak.authenticator;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.Arrays;
import java.util.Random;

public class KeycloakEmailAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(KeycloakEmailAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "email_validation";

    private static enum CODE_STATUS {
        VALID, INVALID, EXPIRED
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate called ... context = " + context);

        if (context.getUser().getEmail() != null) {
            // Store user email in auth session
            context.getAuthenticationSession().setAuthNote(
                    EmailAuthenticatorContstants.AUTH_NOTE_USER_EMAIL,
                    context.getUser().getEmail());

            // Retrieve code validity properties from config (with defaults)
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            String validInMinStr = "5"; // default value
            String activationDelayStr = "2"; // default value
            if (configModel != null && configModel.getConfig() != null) {
                if (configModel.getConfig()
                        .containsKey(EmailAuthenticatorContstants.CODE_VALIDINMIN)) {
                    validInMinStr = configModel.getConfig()
                            .get(EmailAuthenticatorContstants.CODE_VALIDINMIN);
                }
                if (configModel.getConfig()
                        .containsKey(EmailAuthenticatorContstants.CODE_ACTIVATIONDELAYINSEC)) {
                    activationDelayStr = configModel.getConfig()
                            .get(EmailAuthenticatorContstants.CODE_ACTIVATIONDELAYINSEC);
                }
            }

            if (context.getAuthenticationSession()
                    .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE) != null
                    && isTimestampValid(
                            context.getAuthenticationSession()
                                    .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_TIMESTAMP),
                            Integer.parseInt(validInMinStr),
                            Integer.parseInt(activationDelayStr))) {
                // Skip sending a new email code; challenge with the existing one.
                Response challenge = context.form().createForm("mfa-validation.ftl");
                context.challenge(challenge);
                return;
            }
            storeAndSendCode(context);
        } else {
            Response challenge =
                    context.form().setError("E-postadress saknas").createForm("mfa-validation.ftl");
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED,
                    challenge);
            return;
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);

        MultivaluedMap<String, String> formData =
                context.getHttpRequest().getDecodedFormParameters();

        if (formData.containsKey("SendNewCode")) {
            storeAndSendCode(context);
            return;
        }

        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                challenge = context.form().setError("Koden är inte längre giltig")
                        .createForm("mfa-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;
            case INVALID:
                // For ALTERNATIVE, call attempted(); for REQUIRED, fail the authentication.
                if (context.getExecution()
                        .getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.debug("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution()
                        .getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    challenge = context.form().setError("Fel verifieringskod")
                            .createForm("mfa-validation.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                            challenge);
                } else {
                    logger.warn("Undefined execution requirement.");
                }
                break;
            case VALID:
                context.success();
                break;
        }
    }

    private void storeAndSendCode(AuthenticationFlowContext context) {
        long nrOfDigits = 4;
        logger.debug("Using nrOfDigits " + nrOfDigits);

        String code = getCode(nrOfDigits);
        logger.debug("New code: " + code);

        storeCode(context, code);

        if (sendCode(context.getUser().getEmail(), code, context.getAuthenticatorConfig())) {
            Response challenge = context.form().createForm("mfa-validation.ftl");
            context.challenge(challenge);
        } else {
            Response challenge = context.form().setError("E-post kunde inte skickas.")
                    .createForm("mfa-validation.ftl");
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
        }
    }

    private void storeCode(AuthenticationFlowContext context, String code) {
        context.getAuthenticationSession()
                .setAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE, code);
        context.getAuthenticationSession().setAuthNote(
                EmailAuthenticatorContstants.AUTH_NOTE_TIMESTAMP,
                Long.toString(System.currentTimeMillis()));
    }

    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ...");
        MultivaluedMap<String, String> formData =
                context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(EmailAuthenticatorContstants.ANSW_EMAIL_CODE);

        if (enteredCode != null && context.getAuthenticationSession()
                .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE) != null) {
            // Retrieve configuration for code validation from the config
            AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
            String validInMinStr = "5"; // default
            String activationDelayStr = "2"; // default
            if (configModel != null && configModel.getConfig() != null) {
                if (configModel.getConfig()
                        .containsKey(EmailAuthenticatorContstants.CODE_VALIDINMIN)) {
                    validInMinStr = configModel.getConfig()
                            .get(EmailAuthenticatorContstants.CODE_VALIDINMIN);
                }
                if (configModel.getConfig()
                        .containsKey(EmailAuthenticatorContstants.CODE_ACTIVATIONDELAYINSEC)) {
                    activationDelayStr = configModel.getConfig()
                            .get(EmailAuthenticatorContstants.CODE_ACTIVATIONDELAYINSEC);
                }
            }

            logger.debug("Expected code = "
                    + context.getAuthenticationSession()
                            .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE)
                    + "    entered code = " + enteredCode);
            if (isValid(enteredCode,
                    context.getAuthenticationSession()
                            .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE),
                    context.getAuthenticationSession()
                            .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_TIMESTAMP),
                    Integer.parseInt(validInMinStr), Integer.parseInt(activationDelayStr))) {
                result = CODE_STATUS.VALID;
            } else {
                result = CODE_STATUS.INVALID;
            }
        }
        logger.debug("validateCode result: " + result);
        return result;
    }

    @Override
    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user="
                + user);
        boolean result = true;
        logger.debug("configuredFor returning " + result);
        return result;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("setRequiredActions called ... session=" + session + ", realm=" + realm
                + ", user=" + user);
    }

    @Override
    public void close() {
        logger.debug("close called ...");
    }

    private String getCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }
        double maxValue = Math.pow(10.0, nrOfDigits);
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    public boolean sendCode(String email, String code, AuthenticatorConfigModel config) {
        try {
            // Retrieve API URL from config instead of external configLoader
            String apiUrl = null;
            if (config != null && config.getConfig() != null) {
                apiUrl = config.getConfig().get(EmailAuthenticatorContstants.API_URL);
            }
            if (apiUrl == null || apiUrl.isEmpty()) {
                logger.warn("API URL is not configured.");
                return false;
            }

            logger.debug("Using API URL: " + apiUrl);

            CloseableHttpClient client = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(apiUrl);

            String json = getJsonstring(email, code);
            logger.debug("Request JSON: " + json);

            org.apache.http.entity.StringEntity entity =
                    new org.apache.http.entity.StringEntity(json, ContentType.APPLICATION_JSON);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            CloseableHttpResponse response = client.execute(httpPost);
            client.close();
            if (response.getStatusLine().getStatusCode() == 201) {
                logger.debug("Response: " + response.getStatusLine().getReasonPhrase());
                return true;
            } else {
                logger.debug("Response: " + response.getStatusLine().getReasonPhrase());
                return false;
            }

        } catch (Exception e) {
            logger.error("Exception when sending email code", e);
            return false;
        }
    }

    public boolean isValid(String codeInput, String emailedCode, String timeStamp,
            int timeoutInMinutes, int codeActivationDelayInSeconds) {
        codeInput = codeInput.replace("-", "");
        long timePassedSinceRequest = System.currentTimeMillis() - Long.parseLong(timeStamp);
        boolean codeActive = timePassedSinceRequest < 1000 * 60 * timeoutInMinutes
                && timePassedSinceRequest > 1000 * codeActivationDelayInSeconds;
        return codeInput.equalsIgnoreCase(emailedCode) && codeActive;
    }

    public boolean isTimestampValid(String timeStamp, int timeoutInMinutes,
            int codeActivationDelayInSeconds) {
        long timePassedSinceRequest = System.currentTimeMillis() - Long.parseLong(timeStamp);
        return timePassedSinceRequest < 1000 * 60 * timeoutInMinutes
                && timePassedSinceRequest > 1000 * codeActivationDelayInSeconds;
    }

    private static String getJsonstring(String email, String verificationCode) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode templateJson = mapper.createObjectNode();
        templateJson.put("templateId", 1);

        ObjectNode to = mapper.createObjectNode();
        to.put("email", email);
        ArrayNode arrayNode = mapper.createArrayNode();
        arrayNode.addAll(Arrays.asList(to));
        templateJson.set("to", arrayNode);

        ObjectNode parameters = mapper.createObjectNode();
        parameters.put("code", verificationCode);
        templateJson.set("parameters", parameters);

        try {
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(templateJson);
        } catch (JsonProcessingException e) {
            logger.error(e);
            return null;
        }
    }
}
