from pysnmp.hlapi import UsmUserData
from pysnmp.hlapi import CommunityData

# SHOULD FAIL
a = CommunityData('public', mpModel=0)
# SHOULD FAIL
insecure = UsmUserData("securityName")
# SHOULD PASS
less_insecure = UsmUserData("securityName","authName","privName")