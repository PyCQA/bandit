#!/usr/bin/env python3
# -*- coding: latin-1 -*-
# cf. https://trojansource.codes & https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574
# Some special characters: àçéêèù
access_level = "user"
if access_level != 'none??': # Check if admin ??' and access_level != 'user
    print("You are an admin.\n")
