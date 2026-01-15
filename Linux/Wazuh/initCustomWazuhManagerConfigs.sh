insert_block_before_line() {
    local block="$1"
    local search="$2"
    local file="$3"

    awk -v block="$block" -v search="$search" '
        BEGIN { inserted = 0 }
        {
            if (!inserted && $0 ~ search) {
                print block
                inserted = 1
            }
            print
        }
    ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}


LOCAL_RULE_FILE="/var/ossec/etc/rules/local_rules.xml"
CONF="/var/ossec/etc/ossec.conf"


LOCAL_RULE_BLOCK="  <rule id="100002" level="6">
    <if_sid>5715</if_sid>
    <srcip negate="yes">192.168.0.0/16</srcip>
    <description>sshd: authentication sucess from non local ip</description>
    <group>ssh_success,authentication_success,</group>
  </rule>
"
LOCAL_RULE_SEARCH="</group>"


CONF_BLOCK="  <command>
    <name>block-ssh</name>
    <executable>block-ssh.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  <active-response>
    <command>block-ssh</command>
    <location>local</location>
    <rules_id>100002</rules_id>
  </active-response>
"
CONF_SEARCH="</ossec_config>"


insert_block_before_line "$LOCAL_RULE_BLOCK" "$LOCAL_RULE_SEARCH" "$LOCAL_RULE_FILE"
insert_block_before_line "$CONF_BLOCK" "$CONF_SEARCH" "$CONF"

#Enable Archive/All Logs

replace_line() {
    local search="$1"
    local replace="$2"
    local file="$3"

    sed -i "s|$search|$replace|" "$file"
}
CONF="/var/ossec/etc/ossec.conf"

replace_line "<logall>no</logall>" "<logall>yes</logall>" "$CONF"
replace_line "<logall_json>no</logall_json>" "<logall_json>yes</logall_json>" "$CONF"

sed -i '/module: wazuh/,/^[^ ]/ s/enabled: false/enabled: true/' /etc/filebeat/filebeat.yml
