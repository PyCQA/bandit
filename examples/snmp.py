from pysnmp.hlapi import CommunityData, UsmUserData

# SHOULD FAIL
a = CommunityData('public', mpModel=0)
# SHOULD FAIL
b = CommunityData('public')
# SHOULD FAIL
c = CommunityData('public', 1)
# SHOULD FAIL
insecure = UsmUserData("securityName")
# SHOULD FAIL
auth_no_priv = UsmUserData("securityName","authName")
# SHOULD FAIL
auth_no_priv_none = UsmUserData("securityName", "authName", None)
# SHOULD PASS
secure_kwargs = UsmUserData(userName="securityName", authKey="authName", privKey="privName")
# SHOULD PASS
less_insecure = UsmUserData("securityName","authName","privName")
