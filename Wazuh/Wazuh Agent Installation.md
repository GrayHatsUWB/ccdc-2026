
# Installation

Before running these Commands, Change \'IP' to the IP of the wazuh server (i.e. WAZUH_MANAGER='192.168.1.10') and \'Agent-Name' to your machine hostname (i.e. WAZUH_AGENT_NAME='Database-Macine'). This way in wazuh we can easily see what agent is for what machine

**Agent Name Requirements** ([More Info](https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/client.html#manager-address))
The minimum length is 2 characters. Allowed characters are A-Z, a-z, 0-9, ".", "-", "_"

**IP Requirements**
This is the address the agent uses to communicate with the server. Enter an IP address or a fully qualified domain name (FQDN).

**Version**
This should work for Wazuh 4.14.1 (most recent version), however if Wazuh is running a different version, the version code will have to be changed

## Linux

**RPM amd64**
```
curl -o wazuh-agent-4.14.0-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.0-1.x86_64.rpm && sudo WAZUH_MANAGER='IP' WAZUH_AGENT_NAME='Agent-Name' rpm -ihv wazuh-agent-4.14.0-1.x86_64.rpm
```

**RPM aarch64**
```
curl -o wazuh-agent-4.14.0-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.0-1.aarch64.rpm && sudo WAZUH_MANAGER='IP' WAZUH_AGENT_NAME='Agent-Name' rpm -ihv wazuh-agent-4.14.0-1.aarch64.rpm
```

**DEB amd64**
```
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb && sudo WAZUH_MANAGER='IP' WAZUH_AGENT_NAME='Agent-Name' dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
```

**DEB aarch64**
```
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_arm64.deb && sudo WAZUH_MANAGER='IP' WAZUH_AGENT_NAME='Agent-Name' dpkg -i ./wazuh-agent_4.14.0-1_arm64.deb
```

### Start Agent Commands
```
sudo systemctl daemon-reload 
sudo systemctl enable wazuh-agent 
sudo systemctl start wazuh-agent
```


## Windows

```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='IP' WAZUH_AGENT_NAME='Agent-Name'
```

### Start Agent Command
```
NET START Wazuh
```






