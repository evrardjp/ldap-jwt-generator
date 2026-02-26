# LDAP-JWT-generator

This is a tool to generate JWT tokens for promote auth.
A user connects to this service with multiple headers:
- Authorization: Basic <credential>
- TenantName: <entity>

When the API receives this, it will read Basic Auth, forward to Bind(), fetch all the user groups based on a LDAP Search for <entity> (pre-configured by a config file)

## Parameters

| Name                               | Description                          | Example                          | Mandatory   | Default     |
| :--------------                    | :-----------------------------:      | ----------------------------:    | ---------:  | ----------: |
|  **PUBLIC_APISERVER_URL**          |  *Api server url (public)*           | `https://k8s.macompany.com`      | `yes  `     | -           |
|  **LDAP_USERBASE**                 |  *BaseDn for user base search*       | `ou=People,dc=example,dc=org   ` | `yes  `     | -           |
|  **LDAP_GROUPBASE**                |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `yes  `     | -           |
|  **LDAP_APP_GROUPBASE**            |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_OPS_GROUPBASE**            |  *BaseDn for group base search*      | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_CUSTOMER_OPS_GROUPBASE**   |  *BaseDn for customer group base *   | `ou=CONTAINER,dc=example,dc=org` | `no  `      | -           |
|  **LDAP_ADMIN_USERBASE**           |  *BaseDn for admin base search*      | `ou=Admin,dc=example,dc=org   `  | `yes  `     | -           |
|  **LDAP_ADMIN_GROUPBASE**          |  *BaseDn for admin group base search*| `ou=AdminGroup,dc=example,dc=org`| `yes  `     | -           |
|  **LDAP_VIEWER_GROUPBASE**         |  *BaseDn for viewer group base search*| `ou=ViewerGroup,dc=example,dc=org`| `no  `     | -           |
|  **LDAP_SERVICE_GROUPBASE**        |  *BaseDn for service group base search*| `ou=ServiceGroup,dc=example,dc=org`| `no  `     | -           |
|  **LDAP_ELIGIBLE_GROUPS_PARENTS**        |  *List of "\|" separated BaseDn for user groups memberships search*| `ou=container,ou=Groups,dc=kubi,dc=ca-gip,dc=github,dc=com\|ou=teams,ou=Groups,dc=kubi,dc=ca-gip,dc=github,dc=com`| `yes  `     | -           |
|  **LDAP_SERVER**                   |  *LDAP server ip address*            | `"192.168.2.1"                 ` | `yes  `     | -           |
|  **LDAP_PORT**                     |  *LDAP server port 389, 636...*      | `389                           ` | `no   `     | `389  `     |
|  **LDAP_PAGE_SIZE**                |  *LDAP page size, 1000...*           | `1000                           `| `no   `     | `1000  `    |
|  **LDAP_USE_SSL**                  |  *Use SSL or no*                     | `true                          ` | `no   `     | `false`     |
|  **LDAP_START_TLS**                |  *Use StartTLS ( use with 389 port)* | `true                          ` | `false`     | `false`     |
|  **LDAP_SKIP_TLS_VERIFICATION**    |  *Skip TLS verification*             | `true                          ` | `false`     | `true`      |
|  **LDAP_BINDDN**                   |  *LDAP bind account DN*              | `"CN=admin,DC=example,DC=ORG"  ` | `yes  `     | -           |
|  **LDAP_PASSWD**                   |  *LDAP bind account password*        | `"password"                    ` | `yes  `     | -           |
|  **LDAP_USERFILTER**               |  *LDAP filter for user search*       | `"(userPrincipalName=%s)"      ` | `no   `     | `(cn=%s)`   |
|  **TOKEN_LIFETIME**                |  *Duration for the JWT token*        | `"4h"                          ` | `no   `     | 4h          |
|  **LOCATOR**                       |  *Locator: must be internet or extranet*  | `"intranet"             `   | `no   `     | intranet    |
|  **PROVISIONING_NETWORK_POLICIES** |  *Enable or disable NetPol Mgmt*     | `true                           `   | `no   `     | yes         |
|  **CUSTOM_LABELS**                 | *Add custom labels to namespaces*    | `quota=managed,monitoring=true`  | `no   `     | -           |
|  **DEFAULT_PERMISSION**            | *ClusterRole associated with default service account*    | `view`       | `no   `     | -           |
|  **BLACKLIST**                     | *Ignore Project*                     | `my-project-dev`                 | `no   `     | -           |
|  **PODSECURITYADMISSION_ENFORCEMENT**                     | *PodSecurityAdmission  Enforcement*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PODSECURITYADMISSION_WARNING**                     | *PodSecurityAdmission Warning*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PODSECURITYADMISSION_AUDIT**                     | *PodSecurityAdmission Audit*                     | `restricted`                 | `no   `     | `restricted  `           |
|  **PRIVILEGED_NAMESPACES**                     | *Namespaces allowed to use privileged annotation*                     | `native-development`                 | `no   `     | -           |
 
