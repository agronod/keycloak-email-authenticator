package com.agronod.keycloak.authenticator;

/**
 * Created by joris on 18/11/2016.
 */
public class EmailAuthenticatorContstants {
    public static final String ANSW_EMAIL_CODE = "user.attributes.code";

    // Configurable fields
    public static final String CODE_ACTIVATIONDELAYINSEC = "CODE.VALIDINMIN";
    public static final String CODE_VALIDINMIN = "CODE.ACTIVATIONDELAYINSEC";
    public static final String API_URL = "API.URL";

    // email spec codes
    public static final String AUTH_NOTE_USER_EMAIL = "user-email";
    public static final String AUTH_NOTE_EMAIL_CODE = "email-code";
    public static final String AUTH_NOTE_TIMESTAMP = "timestamp";

}
