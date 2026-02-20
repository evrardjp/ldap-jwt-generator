FROM scratch

COPY ./bin/ldap-jwt-generator /bin/ldap-jwt-generator
CMD ["ldap-jwt-generator"]
