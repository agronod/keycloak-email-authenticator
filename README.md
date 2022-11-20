# keycloak-sms-authenticator

To install the EMAIL Authenticator:

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