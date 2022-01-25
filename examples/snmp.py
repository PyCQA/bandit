from pysnmp.hlapi import CommunityData, UsmUserData

# SHOULD FAIL
a = CommunityData('public', mpModel=0)
# SHOULD FAIL
insecure = UsmUserData("securityName")
# SHOULD FAIL
auth_no_priv = UsmUserData("securityName","authName")
# SHOULD PASS
less_insecure = UsmUserData("securityName","authName","privName")
