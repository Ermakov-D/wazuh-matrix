#!/usr/bin/env python3

import sys
import json
import os


# Read configuration parameters
alert_file = open(sys.argv[1])
#hook_url = sys.argv[3]
hook_url = "https://NULL/"


# Read the alert file
alert_json = json.loads(alert_file.read())
alert_file.close()

# Extract data fields
alert_level = alert_json['rule']['level'] if 'level' in alert_json['rule'] else "N/A"
description = alert_json['rule']['description'] if 'description' in alert_json['rule'] else "N/A"
agent = alert_json['agent']['name'] if 'name' in alert_json['agent'] else "N/A"
agent_ip = alert_json['agent']['ip']
src_ip = alert_json['data']['srcip'] if 'src' in alert_json['data'] else "N/A"
rule_id = alert_json['rule']['id']
timestrap = alert_json ['timestamp']

action="N/A"

if rule_id in ["100010", "60115"]:
    action="Блокировка пользователя в домене"
    domain = alert_json['data']['win']['eventdata']['subjectDomainName']
    username = alert_json['data']['win']['eventdata']['targetUserName']
    src_host = alert_json['data']['win']['eventdata']['targetDomainName']
    src_dc = alert_json['data']['win']['eventdata']['subjectUserName']
    message = f"**Wazuh Alert 🚨**\n\n" \
              f"*Описание:* Блокировка уч. записи пользователя\n" \
              f"*Уровень:* {alert_level}\n" \
              f"*Агент:* {agent} ({agent_ip})\n" \
              #f"*IP-адрес агента:* {agent_ip}\n" \
              f"*Домен*: {domain}\n"\
              f"*Домен Контроллер:*: {src_dc}\n"\
              f"*Имя пользователя*: **{username}**\n"\
              f"*Источник*: {src_host}\n"\
              f"*Время*: {timestrap}\n"
elif rule_id in ["5760"]:
    action="Неверная авторизация по ssh"
    dstuser=alert_json['data']['dstuser']
    message = f"*Wazuh предупреждение 🛎*\n\n" \
              f"*Описание:* {description}\n" \
              f"*Уровень:* {alert_level}\n" \
              f"*Агент:* {agent} ({agent_ip})\n" \
              #f"*IP-адрес агента:* {agent_ip}\n" \
              f"*IP-источника:* {src_ip}\n"\
              f"*Время*: {timestrap}\n"
elif rule_id in ["100011","60122"]:
    action="Ошибочка авторизации в домене"
    domain = alert_json['data']['win']['eventdata']['targetDomainName']
    username = alert_json['data']['win']['eventdata']['targetUserName']
    src_host = alert_json['data']['win']['eventdata']['workstationName']
    message = f"**Wazuh предупреждение 💡**\n\n" \
              f"*Описание:* Ошибка авторизации\n" \
              f"*Уровень:* {alert_level}\n" \
              f"*Агент:* {agent}\n" \
              f"*IP-адрес агента:* {agent_ip}\n" \
              f"*Домен*: {domain}\n"\
              f"*Имя пользователя*: <u>{username}</u>\n"\
              f"*Источник*: {src_host}\n"\
              f"*Время*: {timestrap}\n"

else:
    message = f"*📢 <u>Wazuh предупреждение</u> 📢*\n\n" \
              f"*Описание:* {description}\n" \
              f"*Уровень:* {alert_level}\n" \
              f"*Агент:* {agent} ({agent_ip})\n" \
              #f"*IP-адрес агента:* {agent_ip}\n" \
              f"*ID паравила:* {rule_id}\n"\
              f"*Время*: {timestrap}\n"
message=message+"\n---\n"
cmd = r'export https_proxy="http://192.168.250.144:3128";/usr/local/bin/matrix-commander-rs --credentials /var/ossec/etc/matrix-commander-rs/credentials.json --store /var/ossec/etc/matrix-commander-rs/store/ --markdown --message "'+message+'"'
## Debug
#print (cmd)
#try:
#  with open("/tmp/send", "a") as f:
#     f.write(cmd)
#except Exception as e:
#    print("There was an error: ", e)

os.system(cmd)


sys.exit(0)
