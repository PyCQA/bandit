from paramiko import client
from paramiko import AutoAddPolicy
from paramiko import WarningPolicy

ssh_client = client.SSHClient()
ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)
ssh_client.set_missing_host_key_policy(client.WarningPolicy)
ssh_client.set_missing_host_key_policy(client.AutoAddPolicy())
ssh_client.set_missing_host_key_policy(client.WarningPolicy())

ssh_client.set_missing_host_key_policy(AutoAddPolicy)
ssh_client.set_missing_host_key_policy(WarningPolicy)
ssh_client.set_missing_host_key_policy(AutoAddPolicy())
ssh_client.set_missing_host_key_policy(WarningPolicy())
