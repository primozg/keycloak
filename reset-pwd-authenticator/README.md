UPDATE_PASSWORD: Using new OWASP complient Update Password requiredaction
==========================================================================================

Installation
----------------------
1. Copy jar to deployments folder
2. Update base theme with updated themes/base/login/login-update-password.ftl 
3. Deregister existing requiredaction UPDATE_PASSWORD, must be from admin cli, not from gui
curl -k -v --location --header 'Content-Type: application/x-www-form-urlencoded' --header "Authorization: Bearer ${TOKEN}" --request DELETE $LINK_REST/authentication/required-actions/UPDATE_PASSWORD
4. In Admin Console Authentication/Required Actions/Register  add new requred action "Update Password OWASP"
 
What is it?
-----------
In application invoked password change user must enter old password.

System Requirements
-------------------

