#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

mkdir /usr/local/bin/lsrv

cd /usr/local/bin/lsrv

python3 -m venv .

./bin/pip3 install pycryptodome

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/server/server.py

wget https://raw.githubusercontent.com/EthanHoward/SDSN-25/refs/heads/main/server/server_config.ini

chmod +x server.py

sudo tee "/etc/systemd/system/lsrv.service" > /dev/null <<EOF
[Unit]
Description=Log Server Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/lsrv/bin/python3 /usr/local/bin/lsrv/server.py
Restart=on-failure

WorkingDirectory=/usr/local/bin/lsrv
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
EOF

echo "Service Created"

echo "Starting server service to generate keys"

systemctl daemon-reload

systemctl start lsrv

systemctl status lsrv

echo ""
echo "Don't worry about the error (if there is one), that's OK"
echo ""
echo "The server can remain running as the client keys can be dropped in, the server will fail to connect to clients though if it has no key for that client"
echo ""
echo "TODO:"
echo " - Set up your config file, client_config.ini"
echo " - Copy your client public key over to the server key directory, named as client_<contents of /etc/machine-id>_rsa_public_key.pem (should already be named this) "
echo " - Copy your server public key over to the client key directory, named as server_rsa_public_key.pem (should already be named this) "