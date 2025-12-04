#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi
  
mkdir /usr/local/bin/lcli

cd /usr/local/bin/lcli

python3 -m venv .

./bin/pip3 install pycryptodome

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/client/client.py

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/client/client_config.ini

chmod +x client.py

sudo tee "/etc/systemd/system/lcli.service" > /dev/null <<EOF
[Unit]
Description=Log Client Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lcli/client.py
Restart=on-failure

WorkingDirectory=/usr/local/bin/lcli
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

echo "Service Created"

echo "Starting client service to generate keys"

systemctl start lcli

systemctl status lcli

echo "TODO:"
echo " - Set up your config file, client_config.ini"
echo " - Copy your client public key over to the server key directory, named as client_<contents of /etc/machine-id>_rsa_public_key.pem (should already be named this)"
echo " - Copy your server public key over to the client key directory, named as server_rsa_public_key.pem (should already be named this)"
echo ""
echo "Share key via scp local_src user@server:/remote_dest"
echo ""
echo "Copy server key to here via scp user@server:/remote_src local_dest

echo "Alternatively usage of python3 -m http.server 80 can be used to share the keys to/from server"