from oslo_config import cfg


# Correct
secret = True
opts = [
    cfg.StrOpt('admin_user',
               help="User's name"),
    cfg.StrOpt('admin_password',
               secret=True,
               help="User's password"),
    cfg.StrOpt('nova_password',
               secret=secret,
               help="Nova user password"),
]

# Incorrect: password not marked secret
ldap_opts = [
    cfg.StrOpt('ldap_user',
               help="LDAP ubind ser name"),
    cfg.StrOpt('ldap_password',
               help="LDAP bind user password"),
    cfg.StrOpt('ldap_password_attribute',
               help="LDAP password attribute (default userPassword"),
    cfg.StrOpt('user_password',
               secret=False,
               help="User password"),
]
