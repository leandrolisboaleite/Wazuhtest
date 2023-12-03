apt-get install debconf adduser procps
apt-get install gnupg apt-transport-https

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list

apt-get update
apt-get -y install wazuh-indexer

wget https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/wazuh-certs-tool.sh -q -O /tmp/wazuh-certs-tool.sh
wget https://raw.githubusercontent.com/socfortress/Wazuh-Rules/main/config.yml -q -O /tmp/config.yml

2. Update the /tmp/config.yml file to fit your hostname and IP.

3. Run the /tmp/wazuh-certs-tool.sh -A script to generate the certificates.

openssl x509 -in wazuh-indexer01.socfortress.demo -text -noout

NODE_NAME=wazuh-indexer01.socfortress.demo

mkdir /etc/wazuh-indexer/certs
cd /tmp/wazuh-certificates
cp ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem /etc/wazuh-indexer/certs/
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem

chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs


network.host: "0.0.0.0"
node.name: "wazuh-indexer01.socfortress.demo"
cluster.initial_master_nodes:
- "wazuh-indexer01.socfortress.demo"
cluster.name: "socfortress_demo"
discovery.seed_hosts:
- "wazuh-indexer01.socfortress.demo"
node.max_local_storage_nodes: "3"
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

bootstrap.memory_lock: true

plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.resolve_hostname: false

plugins.security.authcz.admin_dn:
- "CN=admin,OU=SOCFortress,O=SOCFortress,L=Texas,C=US"
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.nodes_dn:
- "CN=wazuh-indexer01.socfortress.demo,OU=SOCFortress,O=SOCFortress,L=Texas,C=US"
plugins.security.restapi.roles_enabled:
- "all_access"
- "security_rest_api_access"

plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices: [".plugins-ml-model", ".plugins-ml-task", ".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opensearch-notifications-*", ".opensearch-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]

### Option to allow Filebeat-oss 7.10.2 to work ###
### SOCFortress comments out due to: https://community.graylog.org/t/elasticsearch-exception-reason-key-types-is-not-supported-in-the-metadata-section/27468/6
#compatibility.override_main_response_version: true

/etc/wazuh-indexer/opensearch.yml

bootstrap.memory_lock: true
nano /usr/lib/systemd/system/wazuh-indexer.service
LimitMEMLOCK=infinity

nano /etc/wazuh-indexer/jvm.options


systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

/usr/share/wazuh-indexer/bin/indexer-security-init.sh

apt-get install debhelper tar curl libcap2-bin -y  
apt-get update

apt-get -y install wazuh-dashboard

mkdir /etc/wazuh-dashboard/certs

cp /etc/wazuh-indexer/certs/indexer.pem /etc/wazuh-dashboard/certs/

cp /etc/wazuh-indexer/certs/indexer-key.pem /etc/wazuh-dashboard/certs/

cp /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-dashboard/certs/

chmod 500 /etc/wazuh-dashboard/certs

chmod 400 /etc/wazuh-dashboard/certs/*

chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

/etc/wazuh-dashboard/opensearch_dashboards.yml

server.host: 0.0.0.0
server.port: 443
opensearch.hosts: ["https://wazuh-indexer01.socfortress.demo:9200"]
opensearch.ssl.verificationMode: certificate
#opensearch.username:
#opensearch.password:
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/wazuh-dashboard/certs/indexer-key.pem"
server.ssl.certificate: "/etc/wazuh-dashboard/certs/indexer.pem"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh

systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

/usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --change-all


echo <kibanaserver-password> | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password

systemctl restart wazuh-dashboard

