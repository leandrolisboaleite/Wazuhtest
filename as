wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='172-233-25-58.ip.linodeusercontent.com' WAZUH_AGENT_NAME='Linuxvbox' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
