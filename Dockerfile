FROM scratch

COPY ./bin/ldap-jwt-generator /ldap-jwt-generator
CMD ["/ldap-jwt-generator"]
