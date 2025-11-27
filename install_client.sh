#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

mkdir /usr/local/bin/lcli

cd /usr/local/bin/lcli

python3 -m venv .

./bin/pip3 install pycryptodome

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/client.py

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/client_config.ini

echo "Starting client to generate keys"

chmod +x client.py

./client.py

echo "Remember to configure the client parameters."
echo "Share key via scp client_rsa_public_key.pem user@server:/usr/local/bin/lsvr/"