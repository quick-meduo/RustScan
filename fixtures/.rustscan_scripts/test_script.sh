#!/bin/bash 
#tags = ["core_approved", "example",]
#developers = [ "example", "https://example.org" ]
#trigger_ports = ["80","8080","3307"]
#ports_separator = ","
#call_format = "bash {{script}} {{ip}} {{port}}"

# Sriptfile parser stops at the first blank line with parsing.
# This script will run itself as an argument with the system installed bash interpreter, scanning all ports concatenated with "," .
# Unused filed: trigger_port = "80"

# print all arguments passed to the script
echo $@