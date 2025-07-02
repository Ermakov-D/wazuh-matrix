#!/usr/bin/env python3

import configparser
import asyncio
from nio import AsyncClient
import json
import sys
import os

async def send_message (server,user_id,access_token,room_id,message,proxy=None):
    client = AsyncClient(server,user_id,proxy=proxy)
    client.access_token = access_token
    client.user_id = user_id

    try:
        if not await client.sync(timeout=3000):
            print ("Проблемы с подключением к серверу")
            return

        print (f"Connect as {user_id}")

        response = await client.join (room_id)
        if not response.room_id:
            print (f"Не смог войти в комнату {room_id}")
            return
        await client.room_send (room_id=room_id,message_type="m.room.message",
                                content={
                                    "msgtype": "m.text",
                                    "body": message
                                    }
                               )
    except Exception as e:
        print (f"Что-то пошло не так: {e}")

    finally:
        await client.close()
############################################################################

def read_config (config_file):
    if not os.path.isfile(config_file):
        print(f"Error: Configuration file '{config_file}' not found.")
        exit(1)

    config = configparser.ConfigParser()
    config.read(config_file)
    return {
            "server_url": config.get("matrix","server_url", fallback=None),
            "user_id": config.get("matrix","user_id",fallback=None),
            "access_token": config.get("matrix","access_token",fallback=None),
            "room_id": config.get("matrix", "room_id", fallback=None),
            "proxy": config.get("matrix", "proxy", fallback=None)
           }
############################################################################

alert_file = open(sys.argv[1])
alert_json = json.loads(alert_file.read())
alert_file.close()

#parser = argparse.ArgumentParser(description="Send a notification to a Matrix room.")
#parser.add_argument("--server", help="Matrix server URL (e.g., https://matrix.example.com)")
#parser.add_argument("--user", help="Matrix user ID (e.g., @your_username:example.com)")
#parser.add_argument("--token", help="Matrix access token")
#parser.add_argument("--room",  help="Matrix room ID (e.g., !room_id:example.com)")
#parser.add_argument("--proxy",help="http proxy (e.g., http://proxy.example.com:8080)")
#parser.add_argument("--message", help="Message to send")
#parser.add_argument("--config",default="custom-matrix.ini",help="Path to configuration file (default: custom-matrix.ini)")

#args = parser.parse_args()
config = read_config("custom-matrix.ini")

# Извлечение аргументов из парсера
#MATRIX_SERVER_URL = args.server or config.get("server_url")
#MATRIX_USER_ID = args.user or config.get("user_id")
#MATRIX_ACCESS_TOKEN = args.token or config.get("access_token")
#MATRIX_ROOM_ID = args.room or config.get("room_id")
#PROXY=args.proxy or config.get("proxy")
#MESSAGE = args.message
MATRIX_SERVER_URL = config.get("server_url")
MATRIX_USER_ID = config.get("user_id")
MATRIX_ACCESS_TOKEN = config.get("access_token")
MATRIX_ROOM_ID = config.get("room_id")
PROXY=config.get("proxy")


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
              f"*ID паравила:* {rule_id}\n"\
              f"*Время*: {timestrap}\n"
message=message+"\n---\n"


# Запускаем асинхронную функцию
asyncio.run(send_message(
        MATRIX_SERVER_URL,
        MATRIX_USER_ID,
        MATRIX_ACCESS_TOKEN,
        MATRIX_ROOM_ID,
        message,
        proxy=PROXY
))

