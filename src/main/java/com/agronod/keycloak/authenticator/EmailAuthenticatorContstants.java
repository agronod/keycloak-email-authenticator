package com.agronod.keycloak.authenticator;

/**
 * Created by joris on 18/11/2016.
 */
public class EmailAuthenticatorContstants {
    public static final String ANSW_EMAIL_CODE = "user.attributes.code";

    // Configurable fields

    public static final String CONF_PRP_EMAIL_CODE_TTL = "email-auth.code.ttl";
    public static final String CONF_PRP_EMAIL_CODE_LENGTH = "email-auth.code.length";
    public static final String CONF_PRP_EMAIL_ACTIVA_SEC = "email-auth.code.acttime";

    // email spec codes
    public static final String AUTH_NOTE_USER_EMAIL = "user-email";
    public static final String AUTH_NOTE_EMAIL_CODE = "email-code";
    public static final String AUTH_NOTE_TIMESTAMP = "timestamp";

}
