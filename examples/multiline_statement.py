import subprocess

subprocess.check_output("/some_command",
                        "args",
                        shell=True,
                        universal_newlines=True)
