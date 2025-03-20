# keycloak-sms-authenticator

## Test locally

```bash
mvn clean package -Pdev && docker remove keycloak ~; docker run --name keycloak \
  -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KEYCLOAK_LOGLEVEL=DEBUG \
  -v "$(pwd)/target/keycklok-email-authentication-jar-with-dependencies.jar:/opt/keycloak/providers/keycklok-email-authentication-jar-with-dependencies.jar" \
  quay.io/keycloak/keycloak:26.0.0 \
  start-dev
```

## Installation

* Add the jar to the Keycloak server:
  * `$ cp target/keycloak-email-authenticator.jar _KEYCLOAK_HOME_/providers/`

* Add b2b-keycloak-theme to the Keycloak server:
  
Configure your REALM to use the EMAIL Authentication.
First create a new REALM (or select a previously created REALM).

Under Authentication > Flows:

* Copy 'Browse' flow to 'Browser with Email' flow
* Click on 'Actions > Add execution on the 'Browser with Email Forms' line and add the 'EMAIL Authentication'
* Set 'Email Authentication' to 'REQUIRED' or 'ALTERNATIVE'
* To configure the Email Authenticator, click on Actions  Config and fill in the attributes.

Under Authentication > Bindings:

* Select 'Browser with EMAIL' as the 'Browser Flow' for the REALM.
