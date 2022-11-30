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

import com.agronod.keycloak.config.configLoader;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.util.Arrays;
import java.util.Random;

/**
 * Created by joris on 11/11/2016.
 */
public class KeycloakEmailAuthenticator implements Authenticator {

    private static Logger logger = Logger.getLogger(KeycloakEmailAuthenticator.class);

    public static final String CREDENTIAL_TYPE = "email_validation";

    private static enum CODE_STATUS {
        VALID,
        INVALID,
        EXPIRED
    }

    public void authenticate(AuthenticationFlowContext context) {
        logger.debug("authenticate called ... context = " + context);

        if (context.getUser().getEmail() != null) {
            // The email address exists for current user
            System.out.println(context.getUser().getEmail());
            // store email on authsession
            context.getAuthenticationSession().setAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_USER_EMAIL,
                    context.getUser().getEmail());

            long nrOfDigits = 4; // EmailAuthenticatorUtil.getConfigLong(config,
            // EmailAuthenticatorContstants.CONF_PRP_EMAIL_CODE_LENGTH, 4L);
            logger.debug("Using nrOfDigits " + nrOfDigits);

            // if (context.getAuthenticationSession().getAuthNote(
            // EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE) != null) {
            // // skip sending email code
            // Response challenge = context.form().createForm("mfa-validation.ftl");
            // context.challenge(challenge);
            // return;
            // }

            String code = getCode(nrOfDigits);
            System.out.println("new code:" + code);
            System.out.println(context.getAuthenticationSession().getAuthNote(
                    EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE));

            storeCode(context, code);

            if (sendCode(context.getUser().getEmail(), code, context.getAuthenticatorConfig())) {
                System.out.println("Email sent");
                Response challenge = context.form().createForm("mfa-validation.ftl");
                context.challenge(challenge);
            } else {
                System.out.println("Email not found");
                Response challenge = context.form()
                        .setError("Email could not be sent.")
                        .createForm("mfa-validation-error.ftl");
                context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challenge);
                return;
            }
        } else {
            System.out.println("saknar emaill");
            // The mobile number is NOT configured --> complain
            Response challenge = context.form()
                    .setError("Missing email address")
                    .createForm("mfa-validation-error.ftl");
            context.failureChallenge(AuthenticationFlowError.CLIENT_CREDENTIALS_SETUP_REQUIRED, challenge);
            return;
        }
    }

    public void action(AuthenticationFlowContext context) {
        logger.debug("action called ... context = " + context);
        CODE_STATUS status = validateCode(context);
        Response challenge = null;
        switch (status) {
            case EXPIRED:
                challenge = context.form()
                        .setError("code is expired")
                        .createForm("mfa-validation.ftl");
                context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE, challenge);
                break;

            case INVALID:
                if (context.getExecution().getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE ||
                        context.getExecution()
                                .getRequirement() == AuthenticationExecutionModel.Requirement.ALTERNATIVE) {
                    logger.debug("Calling context.attempted()");
                    context.attempted();
                } else if (context.getExecution()
                        .getRequirement() == AuthenticationExecutionModel.Requirement.REQUIRED) {
                    System.out.println("bad code");
                    challenge = context.form()
                            .setError("badCode")
                            .createForm("mfa-validation-error.ftl");
                    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                } else {
                    // Something strange happened
                    logger.warn("Undefined execution ...");
                }
                break;

            case VALID:
                context.success();
                break;

        }
    }

    // Store the code + expiration time in a UserCredential. Keycloak will persist
    // these in the DB.
    // When the code is validated on another node (in a clustered environment) the
    // other nodes have access to it's values too.
    private void storeCode(AuthenticationFlowContext context, String code) {
        // context.getAuthenticationSession().setAuthNote(, code).
        context.getAuthenticationSession().setAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE, code);
        context.getAuthenticationSession().setAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_TIMESTAMP,
                Long.toString(System.currentTimeMillis()));
    }

    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        logger.debug("validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(EmailAuthenticatorContstants.ANSW_EMAIL_CODE);

        if (enteredCode != null && context.getAuthenticationSession()
                .getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE) != null) {
            logger.debug("Expected code = "
                    + context.getAuthenticationSession().getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE)
                    + "    entered code = " + enteredCode);
            if (isValid(enteredCode,
                    context.getAuthenticationSession().getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_EMAIL_CODE),
                    context.getAuthenticationSession().getAuthNote(EmailAuthenticatorContstants.AUTH_NOTE_TIMESTAMP), 5,
                    2)) {
                result = CODE_STATUS.VALID;
            } else {
                result = CODE_STATUS.INVALID;
            }

        }
        logger.debug("result : " + result);
        return result;
    }

    public boolean requiresUser() {
        logger.debug("requiresUser called ... returning true");
        return true;
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("configuredFor called ... session=" + session + ", realm=" + realm + ", user=" + user);
        boolean result = true;
        logger.debug("... returning " + result);
        return result;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        logger.debug("setRequiredActions called ... session=" + session + ", realm=" + realm + ", user=" + user);
    }

    public void close() {
        logger.debug("close called ...");
    }

    private String getCode(long nrOfDigits) {
        if (nrOfDigits < 1) {
            throw new RuntimeException("Nr of digits must be bigger than 0");
        }

        double maxValue = Math.pow(10.0, nrOfDigits); // 10 ^ nrOfDigits;
        Random r = new Random();
        long code = (long) (r.nextFloat() * maxValue);
        return Long.toString(code);
    }

    public boolean sendCode(String email, String code, AuthenticatorConfigModel config) {
        try {

            CloseableHttpClient client = HttpClients.createDefault();

            HttpPost httpPost = new HttpPost(
                    configLoader.getInstance().getProperty("API.URL"));

            String json = getJsonstring(email, code);
            org.apache.http.entity.StringEntity entity = new org.apache.http.entity.StringEntity(json,
                    ContentType.APPLICATION_JSON);
            httpPost.setEntity(entity);
            httpPost.setHeader("Accept", "application/json");
            httpPost.setHeader("Content-type", "application/json");

            CloseableHttpResponse response = client.execute(httpPost);
            client.close();
            if (response.getStatusLine().getStatusCode() == 201) {
                System.out.println(response.getStatusLine().getReasonPhrase());
                return true;
            } else {
                System.out.println(response.getStatusLine().getReasonPhrase());
                return false;
            }

        } catch (Exception e) {
            System.out.println("Exception when calling TransactionalEmailsApi#sendTransacEmail" + e);
            return false;
        }

    }

    public boolean isValid(String codeInput, String emailedCode, String timeStamp, int timeoutInMinutes,
            int codeActivationDelayInSeconds) {

        codeInput = codeInput.replace("-", "");

        long timePassedSinceRequest = System.currentTimeMillis()
                - Long.parseLong(timeStamp);

        boolean codeActive = timePassedSinceRequest < 1000 * 60 * timeoutInMinutes
                && timePassedSinceRequest > 1000 * codeActivationDelayInSeconds;

        return (codeInput.equalsIgnoreCase(emailedCode) && codeActive);

    }

    private static String getJsonstring(String email, String verificationCode) {

        // create `ObjectMapper` instance
        ObjectMapper mapper = new ObjectMapper();

        // create a JSON object
        ObjectNode templateJson = mapper.createObjectNode();
        templateJson.put("templateId", 1);

        // create a child JSON object
        ObjectNode to = mapper.createObjectNode();
        // to.put("name", "???"); //Är dett nödvändigt
        to.put("email", email);

        // create `ArrayNode` object
        ArrayNode arrayNode = mapper.createArrayNode();

        // add JSON users to array
        arrayNode.addAll(Arrays.asList(to));

        // append address to user
        templateJson.set("to", arrayNode);

        ObjectNode parameters = mapper.createObjectNode();
        parameters.put("code", verificationCode);

        templateJson.set("parameters", parameters);

        // convert `ObjectNode` to pretty-print JSON
        try {
            String jsonStr = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(templateJson);
            return jsonStr;
        } catch (JsonProcessingException e) {
            logger.error(e);
            return null;
        }

    }

}
