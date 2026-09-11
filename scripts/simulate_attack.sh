#!/usr/bin/env bash
# ApexShield Automated Attack Script (Bash / cURL)
BASE_URL="http://127.0.0.1:8000"
TARGET_USER="alex.mercer"

echo -e "\e[36m========================================================\e[0m"
echo -e "\e[32m APEXSHIELD SOC ATTACK GENERATOR (BASH / CURL) \e[0m"
echo -e "\e[36m========================================================\e[0m"

echo -e "\e[31m[*] Firing rapid 6-shot credential blast against ${TARGET_USER}...\e[0m"
for i in {1..6}; do
    curl -s -X POST "${BASE_URL}/api/v1/auth/login"          -H "Content-Type: application/json"          -H "User-Agent: curl-brute-force/7.88.1"          -H "X-Forwarded-For: 198.51.100.89"          -d "{"username": "${TARGET_USER}", "password": "invalid_pass_${i}"}" > /dev/null
    echo -e "Attempt ${i} dispatched at $(date +%H:%M:%S.%3N)"
    sleep 0.1
done

echo -e "
\e[32m[+] Querying SOC incident queue for generated alert...\e[0m"
curl -s "${BASE_URL}/api/v1/soc/incidents" | grep -o ""incident_number":"[^"]*"" | head -n 1
