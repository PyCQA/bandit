from pysnmp.hlapi import CommunityData, UsmUserData

# SHOULD FAIL
a = CommunityData('public', mpModel=0)
# SHOULD FAIL: mpModel defaults to insecure SNMPv2c
default_v2c = CommunityData("public")
# SHOULD FAIL: communityName is positional and mpModel still defaults to v2c
named_v2c = CommunityData("index", "public")
# SHOULD FAIL: mpModel is the third positional argument
positional_v2c = CommunityData("index", "public", 1)
# SHOULD FAIL: None also selects the insecure default
explicit_default = CommunityData("public", mpModel=None)
# SHOULD PASS
other_model = CommunityData("index", "public", 3)
# SHOULD PASS: a dynamic model cannot be classified statically
mp_model = object()
dynamic_model = CommunityData("public", mpModel=mp_model)
# SHOULD FAIL
insecure = UsmUserData("securityName")
# SHOULD FAIL
auth_no_priv = UsmUserData("securityName", "authName")
# SHOULD FAIL
explicit_no_priv = UsmUserData("securityName", "authName", None)
# SHOULD PASS
less_insecure = UsmUserData("securityName", "authName", "privName")
# SHOULD PASS
keyword_priv = UsmUserData(
    userName="securityName", authKey="authName", privKey="privName"
)
# SHOULD PASS: a dynamic privacy key may be present at runtime
priv_key = object()
dynamic_priv = UsmUserData(
    userName="securityName", authKey="authName", privKey=priv_key
)
