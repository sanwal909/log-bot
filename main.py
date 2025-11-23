import requests
import time
import logging
import json
import re
import os
from datetime import datetime, timedelta
from typing import Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pella_bot_automation.log'),
        logging.StreamHandler()
    ]
)

class PellaAccount:
    def __init__(self, account_name, email, password, server_id, telegram_chat_id=None, 
                 custom_restart_time=45, auto_restart=True, is_active=True):
        self.account_name = account_name
        self.email = email
        self.password = password
        self.server_id = server_id
        self.telegram_chat_id = telegram_chat_id
        self.custom_restart_time = custom_restart_time
        self.auto_restart = auto_restart
        self.is_active = is_active
        self.current_token = None
        self.session = requests.Session()
        self.last_restart_time: Optional[datetime] = None
        self.restart_count = 0

    def __str__(self):
        return f"PellaAccount({self.account_name}, Server: {self.server_id}, RestartTime: {self.custom_restart_time}min)"

class PellaMultiAutomation:
    def __init__(self):
        self.config_file = "config.json"
        self.base_url = "https://api.pella.app/server"
        self.clerk_url = "https://clerk.pella.app/v1/client"
        
        self.last_request_time = 0
        self.request_delay = 3
        self.bot_running = True
        self.last_update_id = 0
        
        self.load_config()

    def load_config(self):
        if not os.path.exists(self.config_file):
            logging.warning(f"⚠️  Config file not found, creating default config...")
            self.accounts = []
            self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
            self.save_config()
            return
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN") or config.get("telegram_bot_token", "")
            self.accounts = []
            
            for acc_data in config.get("accounts", []):
                account = PellaAccount(
                    account_name=acc_data["account_name"],
                    email=acc_data["email"],
                    password=acc_data["password"],
                    server_id=acc_data["server_id"],
                    telegram_chat_id=acc_data.get("telegram_chat_id"),
                    custom_restart_time=acc_data.get("custom_restart_time", 45),
                    auto_restart=acc_data.get("auto_restart", True),
                    is_active=acc_data.get("is_active", True)
                )
                self.accounts.append(account)
            
            logging.info(f"✅ Loaded {len(self.accounts)} accounts from config")
        
        except Exception as e:
            logging.error(f"❌ Failed to load config: {e}")
            self.accounts = []
            self.telegram_bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    
    def save_config(self):
        try:
            config = {
                "accounts": []
            }
            
            for account in self.accounts:
                acc_data = {
                    "account_name": account.account_name,
                    "email": account.email,
                    "password": account.password,
                    "server_id": account.server_id,
                    "telegram_chat_id": account.telegram_chat_id,
                    "custom_restart_time": account.custom_restart_time,
                    "auto_restart": account.auto_restart,
                    "is_active": account.is_active
                }
                config["accounts"].append(acc_data)
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logging.info("✅ Config saved successfully")
            return True
        
        except Exception as e:
            logging.error(f"❌ Failed to save config: {e}")
            return False

    def rate_limit(self):
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.request_delay:
            sleep_time = self.request_delay - time_since_last_request
            logging.info(f"⏳ Rate limiting: Waiting {sleep_time:.1f}s")
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def send_telegram_message(self, message, chat_id=None):
        if not self.telegram_bot_token:
            logging.warning("⚠️  Telegram bot token not set")
            return False

        if not chat_id:
            logging.warning("⚠️  No chat ID specified")
            return False

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }

        try:
            self.rate_limit()
            response = requests.post(url, data=payload, timeout=10)
            if response.status_code == 200:
                logging.info("📱 Telegram message sent successfully")
                return True
            else:
                logging.error(f"❌ Failed to send Telegram message: {response.text}")
                return False
        except Exception as e:
            logging.error(f"❌ Telegram error: {e}")
            return False

    def send_broadcast_message(self, message):
        success_count = 0
        unique_chats = set()

        for account in self.accounts:
            if account.telegram_chat_id:
                unique_chats.add(account.telegram_chat_id)

        for chat_id in unique_chats:
            if self.send_telegram_message(message, chat_id):
                success_count += 1
            time.sleep(1)

        return success_count

    def extract_session_ids(self, response):
        sia_id = None
        sess_id = None

        try:
            data = response.json()

            if 'response' in data and 'id' in data['response']:
                sia_id = data['response']['id']
            elif 'client' in data and 'sign_in' in data['client'] and 'id' in data['client']['sign_in']:
                sia_id = data['client']['sign_in']['id']

            if 'response' in data and 'created_session_id' in data['response']:
                sess_id = data['response']['created_session_id']
            elif 'client' in data and 'last_active_session_id' in data['client']:
                sess_id = data['client']['last_active_session_id']

        except Exception as e:
            logging.warning(f"⚠️  Could not parse JSON: {e}")

        return sia_id, sess_id

    def extract_jwt_token(self, response):
        try:
            data = response.json()

            if 'token' in data:
                jwt_token = data['token']
                return f"Bearer {jwt_token}"

            if 'client' in data and 'sessions' in data['client'] and data['client']['sessions']:
                for session in data['client']['sessions']:
                    if 'last_active_token' in session and 'jwt' in session['last_active_token']:
                        jwt_token = session['last_active_token']['jwt']
                        return f"Bearer {jwt_token}"

            if 'response' in data and 'last_active_token' in data['response']:
                jwt_token = data['response']['last_active_token']['jwt']
                return f"Bearer {jwt_token}"

            response_text = json.dumps(data)
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            matches = re.findall(jwt_pattern, response_text)
            if matches:
                return f"Bearer {matches[0]}"

        except Exception as e:
            logging.warning(f"⚠️  Could not extract JWT token: {e}")

        return None

    def perform_complete_login(self, account):
        logging.info(f"🔐 [{account.account_name}] Performing complete login...")

        try:
            account.session = requests.Session()

            # STEP 1: Initial sign in
            url1 = f"{self.clerk_url}/sign_ins?__clerk_api_version=2025-11-10&_clerk_js_version=5.109.2"
            payload1 = {
                'identifier': account.email,
                'locale': "en-IN"
            }

            headers1 = {
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                'Accept-Encoding': "identity",
                'Content-Type': 'application/x-www-form-urlencoded',
                'sec-ch-ua-platform': "\"Windows\"",
                'sec-ch-ua': "\"Chromium\";v=\"142\", \"Not_A Brand\";v=\"99\"",
                'sec-ch-ua-mobile': "?0",
                'origin': "https://www.pella.app",
                'x-requested-with': "mark.via.gp",
                'sec-fetch-site': "same-site",
                'sec-fetch-mode': "cors",
                'sec-fetch-dest': "empty",
                'referer': "https://www.pella.app/",
                'accept-language': "en-IN,en-US;q=0.9,en;q=0.8",
                'priority': "u=1, i"
            }

            self.rate_limit()
            response1 = account.session.post(url1, data=payload1, headers=headers1)
            logging.info(f"📧 [{account.account_name}] Step 1 - Sign in: {response1.status_code}")

            if response1.status_code != 200:
                logging.error(f"❌ [{account.account_name}] Sign in failed: {response1.text}")
                return False

            sia_id, sess_id = self.extract_session_ids(response1)
            logging.info(f"🔍 [{account.account_name}] Extracted - SIA: {sia_id}")

            if not sia_id:
                logging.error(f"❌ [{account.account_name}] Could not extract sign in attempt ID")
                return False

            time.sleep(3)

            # STEP 2: Password authentication
            url2 = f"{self.clerk_url}/sign_ins/{sia_id}/attempt_first_factor?__clerk_api_version=2025-11-10&_clerk_js_version=5.109.2"
            payload2 = {
                'strategy': "password",
                'password': account.password
            }

            self.rate_limit()
            response2 = account.session.post(url2, data=payload2, headers=headers1)
            logging.info(f"🔑 [{account.account_name}] Step 2 - Password: {response2.status_code}")

            if response2.status_code != 200:
                logging.error(f"❌ [{account.account_name}] Password authentication failed: {response2.text}")
                return False

            logging.info(f"✅ [{account.account_name}] Password authentication successful!")
            account.current_token = self.extract_jwt_token(response2)

            time.sleep(3)

            # STEP 3: Session touch
            if account.current_token:
                sia_id2, sess_id2 = self.extract_session_ids(response2)
                if sess_id2:
                    url3 = f"{self.clerk_url}/sessions/{sess_id2}/touch?__clerk_api_version=2025-11-10&_clerk_js_version=5.109.2"
                    payload3 = {'active_organization_id': ""}

                    self.rate_limit()
                    response3 = account.session.post(url3, data=payload3, headers=headers1)
                    logging.info(f"🔐 [{account.account_name}] Step 3 - Session Touch: {response3.status_code}")

                    if response3.status_code == 200:
                        logging.info(f"✅ [{account.account_name}] Session established successfully!")
                        new_token = self.extract_jwt_token(response3)
                        if new_token:
                            account.current_token = new_token

            if not account.current_token:
                logging.warning(f"⚠️  [{account.account_name}] No JWT token extracted, will use session cookies")

            return True

        except Exception as e:
            logging.error(f"❌ [{account.account_name}] Login error: {e}")
            return False

    def get_fresh_token(self, account):
        logging.info(f"🔄 [{account.account_name}] Getting fresh authentication token...")

        if self.perform_complete_login(account):
            return True

        logging.info(f"🔄 [{account.account_name}] Complete login failed, trying fallback...")

        try:
            url1 = f"{self.clerk_url}/sign_ins?__clerk_api_version=2025-11-10&_clerk_js_version=5.109.2"
            payload1 = {
                'identifier': account.email,
                'locale': "en-IN"
            }

            headers1 = {
                'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                'Accept-Encoding': "identity",
                'Content-Type': 'application/x-www-form-urlencoded',
                'sec-ch-ua-platform': "\"Windows\"",
                'sec-ch-ua': "\"Chromium\";v=\"142\", \"Not_A Brand\";v=\"99\"",
                'sec-ch-ua-mobile': "?0",
                'origin': "https://www.pella.app",
                'x-requested-with': "mark.via.gp",
                'sec-fetch-site': "same-site",
                'sec-fetch-mode': "cors",
                'sec-fetch-dest': "empty",
                'referer': "https://www.pella.app/",
                'accept-language': "en-IN,en-US;q=0.9,en;q=0.8",
                'priority': "u=1, i"
            }

            self.rate_limit()
            response1 = account.session.post(url1, data=payload1, headers=headers1)
            logging.info(f"📧 [{account.account_name}] Fallback - Sign in: {response1.status_code}")

            if response1.status_code != 200:
                if response1.status_code == 400 and "already signed in" in response1.text:
                    logging.info(f"ℹ️  [{account.account_name}] Already signed in, proceeding...")
                    account.current_token = self.extract_jwt_token(response1)
                    return True
                else:
                    logging.error(f"❌ [{account.account_name}] Fallback sign in failed: {response1.text}")
                    return False

            return True

        except Exception as e:
            logging.error(f"❌ [{account.account_name}] Fallback login error: {e}")
            return False

    def make_api_request(self, account, method, endpoint, payload=None, retry_count=0):
        if retry_count >= 2:
            logging.error(f"❌ [{account.account_name}] Max retries reached for API request")
            return None

        url = f"{self.base_url}/{endpoint}"

        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
            'Accept-Encoding': "identity",
            'Content-Type': "application/json",
            'sec-ch-ua-platform': "\"Windows\"",
            'sec-ch-ua': "\"Chromium\";v=\"142\", \"Not_A Brand\";v=\"99\"",
            'sec-ch-ua-mobile': "?0",
            'origin': "https://www.pella.app",
            'x-requested-with': "mark.via.gp",
            'sec-fetch-site': "same-site",
            'sec-fetch-mode': "cors",
            'sec-fetch-dest': "empty",
            'referer': "https://www.pella.app/",
            'accept-language': "en-IN,en-US;q=0.9,en;q=0.8",
            'priority': "u=1, i"
        }

        if account.current_token:
            headers['authorization'] = account.current_token
            logging.info(f"🔑 [{account.account_name}] Using JWT token for authentication")
        else:
            logging.info(f"🍪 [{account.account_name}] Using session cookies for authentication")

        if payload is None:
            payload = {}

        if 'id' not in payload and endpoint in ['start', 'stop', 'info']:
            payload['id'] = account.server_id

        try:
            self.rate_limit()

            if method.upper() == 'GET':
                if 'id' in payload:
                    url = f"{url}?id={payload['id']}"
                response = account.session.get(url, headers=headers)
            else:
                response = account.session.post(url, data=json.dumps(payload), headers=headers)

            logging.info(f"🌐 [{account.account_name}] API {method} {endpoint}: {response.status_code}")

            if response.status_code == 200:
                logging.info(f"📄 [{account.account_name}] Response preview: {response.text[:200]}...")

            if response.status_code == 401:
                logging.warning(f"🔄 [{account.account_name}] Authentication failed, re-authenticating...")
                if self.get_fresh_token(account):
                    return self.make_api_request(account, method, endpoint, payload, retry_count + 1)
                else:
                    return None

            if response.status_code == 429:
                logging.warning(f"⏳ [{account.account_name}] Rate limited, waiting 60 seconds...")
                time.sleep(60)
                return self.make_api_request(account, method, endpoint, payload, retry_count + 1)

            return response

        except Exception as e:
            logging.error(f"❌ [{account.account_name}] API request error: {e}")
            return None

    def safe_json_parse(self, response):
        try:
            return response.json()
        except json.JSONDecodeError as e:
            logging.error(f"❌ JSON parse error: {e}")
            return None
        except Exception as e:
            logging.error(f"❌ Unexpected parse error: {e}")
            return None

    def get_server_info(self, account):
        logging.info(f"📊 [{account.account_name}] Getting server info...")

        response = self.make_api_request(account, 'GET', 'info', {'id': account.server_id})

        if response and response.status_code == 200:
            data = self.safe_json_parse(response)
            if data:
                status = data.get('status', 'unknown')
                logging.info(f"🟢 [{account.account_name}] Server Status: {status}")
                return status
            else:
                logging.error(f"❌ [{account.account_name}] Could not parse server info response")
                return None
        else:
            if response:
                logging.error(f"❌ [{account.account_name}] Failed to get server info: {response.status_code}")
            else:
                logging.error(f"❌ [{account.account_name}] No response from server info request")
            return None

    def start_server(self, account):
        logging.info(f"▶️  [{account.account_name}] Starting server...")

        response = self.make_api_request(account, 'POST', 'start', {'id': account.server_id})

        if response:
            if response.status_code == 200:
                logging.info(f"✅ [{account.account_name}] Server start command sent successfully")

                if account.telegram_chat_id:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = f"🚀 <b>{account.account_name} - Service Started</b>\n\n⏰ Time: {current_time}\n🆔 Server: {account.server_id}\n📊 Status: Starting..."
                    self.send_telegram_message(message, account.telegram_chat_id)

                data = self.safe_json_parse(response)
                if data:
                    logging.info(f"📋 [{account.account_name}] Start response: {data}")

                logging.info(f"⏳ [{account.account_name}] Waiting 2 minutes for server to fully start...")
                time.sleep(120)

                return True
            else:
                logging.error(f"❌ [{account.account_name}] Failed to start server: {response.status_code} - {response.text}")
                return False
        else:
            logging.error(f"❌ [{account.account_name}] No response from start server request")
            return False

    def stop_server(self, account):
        logging.info(f"⏹️  [{account.account_name}] Stopping server...")

        response = self.make_api_request(account, 'POST', 'stop', {'id': account.server_id})

        if response:
            if response.status_code == 200:
                logging.info(f"🛑 [{account.account_name}] Server stop command sent successfully")

                if account.telegram_chat_id:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    message = f"🛑 <b>{account.account_name} - Service Stopped</b>\n\n⏰ Time: {current_time}\n🆔 Server: {account.server_id}\n📊 Status: Stopping..."
                    self.send_telegram_message(message, account.telegram_chat_id)

                data = self.safe_json_parse(response)
                if data:
                    logging.info(f"📋 [{account.account_name}] Stop response: {data}")

                logging.info(f"⏳ [{account.account_name}] Waiting 1 minute for server to fully stop...")
                time.sleep(60)

                return True
            else:
                logging.error(f"❌ [{account.account_name}] Failed to stop server: {response.status_code} - {response.text}")
                return False
        else:
            logging.error(f"❌ [{account.account_name}] No response from stop server request")
            return False

    def perform_restart_cycle_for_account(self, account):
        logging.info(f"🔄 [{account.account_name}] Starting restart cycle...")

        account.current_token = None

        if not self.get_fresh_token(account):
            logging.error(f"❌ [{account.account_name}] Cannot establish authentication session")
            return False

        current_status = self.get_server_info(account)

        if current_status is None:
            logging.error(f"❌ [{account.account_name}] Cannot determine server status")
            return False

        logging.info(f"📊 [{account.account_name}] Current server status: {current_status}")

        if current_status in ['running', 'starting']:
            logging.info(f"⏹️  [{account.account_name}] Stopping server (current status: {current_status})...")
            if self.stop_server(account):
                logging.info(f"⏳ [{account.account_name}] Server stop completed, proceeding to start...")
            else:
                logging.error(f"❌ [{account.account_name}] Failed to stop server")
                return False
        else:
            logging.info(f"⚠️  [{account.account_name}] Server not running (status: {current_status}), proceeding to start...")

        logging.info(f"▶️  [{account.account_name}] Starting server...")
        if self.start_server(account):
            logging.info(f"⏳ [{account.account_name}] Server start completed, verifying status...")

            new_status = self.get_server_info(account)
            if new_status in ['running', 'starting']:
                logging.info(f"✅ [{account.account_name}] Server restart completed successfully! New status: {new_status}")

                if account.telegram_chat_id:
                    final_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    final_message = f"✅ <b>{account.account_name} - Server Ready</b>\n\n⏰ Time: {final_time}\n🆔 Server: {account.server_id}\n📊 Final Status: {new_status}"
                    self.send_telegram_message(final_message, account.telegram_chat_id)

                return True
            else:
                logging.error(f"❌ [{account.account_name}] Server may not have started properly. Current status: {new_status}")
                return False
        else:
            logging.error(f"❌ [{account.account_name}] Failed to start server")
            return False

    # 🤖 BOT CONTROL FEATURES

    def start_telegram_bot(self):
        logging.info("🤖 Starting Telegram Bot Controller...")

        import threading
        bot_thread = threading.Thread(target=self._telegram_bot_loop)
        bot_thread.daemon = True
        bot_thread.start()

        self.send_bot_startup_message()

    def _telegram_bot_loop(self):
        while self.bot_running:
            try:
                self._check_telegram_commands()
                time.sleep(3)
            except Exception as e:
                logging.error(f"❌ Telegram bot error: {e}")
                time.sleep(10)

    def _check_telegram_commands(self):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/getUpdates?offset={self.last_update_id + 1}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('ok') and data.get('result'):
                    for update in data['result']:
                        if update['update_id'] > self.last_update_id:
                            self.last_update_id = update['update_id']
                            self._process_message(update)
        except Exception as e:
            logging.error(f"❌ Telegram check error: {e}")

    def _process_message(self, update):
        if 'message' not in update or 'text' not in update['message']:
            return

        chat_id = update['message']['chat']['id']
        text = update['message']['text'].strip()

        if text.startswith('/'):
            self._handle_command(chat_id, text)

    def _handle_command(self, chat_id, command):
        original_command = command
        command_lower = command.lower()

        if command_lower == '/start':
            self._send_welcome_message(chat_id)
        elif command_lower == '/status':
            self._send_all_status(chat_id)
        elif command_lower == '/restart_all':
            self._restart_all_accounts(chat_id)
        elif command_lower == '/stop_all':
            self._stop_all_servers(chat_id)
        elif command_lower == '/start_all':
            self._start_all_servers(chat_id)
        elif command_lower.startswith('/restart '):
            account_name = original_command[9:].strip()
            self._restart_single_account(chat_id, account_name)
        elif command_lower.startswith('/login '):
            account_name = original_command[7:].strip()
            self._force_login_account(chat_id, account_name)
        elif command_lower.startswith('/change_time '):
            parts = original_command.split()
            if len(parts) >= 3:
                account_name = ' '.join(parts[1:-1])
                new_time = int(parts[-1])
                self._change_restart_time(chat_id, account_name, new_time)
        elif command_lower.startswith('/auto_restart '):
            parts = original_command.split()
            if len(parts) >= 3:
                account_name = ' '.join(parts[1:-1])
                status = parts[-1].lower() == 'on'
                self._toggle_auto_restart(chat_id, account_name, status)
        elif command_lower == '/help':
            self._send_help_message(chat_id)
        elif command_lower == '/accounts':
            self._send_accounts_list(chat_id)
        elif command_lower == '/add_account':
            self._send_add_account_instructions(chat_id)
        elif command_lower.startswith('/add_account '):
            params = original_command[13:].strip()
            self._add_new_account(chat_id, params)
        elif command_lower.startswith('/remove_account '):
            account_name = original_command[16:].strip()
            self._remove_account(chat_id, account_name)
        else:
            self._send_unknown_command(chat_id)

    def _send_welcome_message(self, chat_id):
        message = """
🤖 <b>PELLA MULTI-ACCOUNT BOT</b>

<b>Available Commands:</b>

➕ <b>Account Management:</b>
/add_account - Add new account (shows format)
/remove_account [AccountName] - Remove account

🔄 <b>Restart Commands:</b>
/restart_all - Restart all accounts
/restart [AccountName] - Restart specific account
/start_all - Start all servers  
/stop_all - Stop all servers

⏰ <b>Time Management:</b>  
/change_time [AccountName] [Minutes] - Change restart time

🔐 <b>Login Management:</b>
/login [AccountName] - Force login to account

📊 <b>Status Commands:</b>
/status - Check all accounts status
/accounts - List all accounts

⚙️ <b>Settings:</b>
/auto_restart [AccountName] on/off - Toggle auto restart
/help - Show this help message
"""
        self.send_telegram_message(message, chat_id)

    def _send_all_status(self, chat_id):
        message = "📊 <b>ACCOUNTS STATUS</b>\n\n"

        for account in self.accounts:
            if not account.is_active:
                continue

            status = self.get_server_info(account) or "Unknown"
            last_restart = account.last_restart_time.strftime("%H:%M") if account.last_restart_time else "Never"

            message += f"<b>{account.account_name}</b>\n"
            message += f"🔄 Status: {status}\n"
            message += f"⏰ Restart Time: {account.custom_restart_time}min\n"
            message += f"🕒 Last Restart: {last_restart}\n"
            message += f"🔢 Restart Count: {account.restart_count}\n"
            message += f"🤖 Auto Restart: {'✅ ON' if account.auto_restart else '❌ OFF'}\n"
            message += "────────────────────\n"

        self.send_telegram_message(message, chat_id)

    def _send_accounts_list(self, chat_id):
        message = "📝 <b>ALL ACCOUNTS</b>\n\n"

        for i, account in enumerate(self.accounts, 1):
            message += f"{i}. <b>{account.account_name}</b>\n"
            message += f"   ⏰ Time: {account.custom_restart_time}min\n"
            message += f"   🤖 Auto: {'✅' if account.auto_restart else '❌'}\n"
            message += f"   🟢 Active: {'✅' if account.is_active else '❌'}\n\n"

        self.send_telegram_message(message, chat_id)

    def _restart_all_accounts(self, chat_id):
        self.send_telegram_message("🔄 <b>Restarting ALL accounts...</b>", chat_id)

        success_count = 0
        active_accounts = [acc for acc in self.accounts if acc.is_active]
        total_active = len(active_accounts)

        for account in active_accounts:
            if self.perform_restart_cycle_for_account(account):
                success_count += 1
                account.restart_count += 1
                account.last_restart_time = datetime.now()
            time.sleep(10)

        message = f"✅ <b>Restart Complete!</b>\n\nSuccessful: {success_count}/{total_active}"
        self.send_telegram_message(message, chat_id)

    def _restart_single_account(self, chat_id, account_name):
        account = self._find_account_by_name(account_name)
        if not account:
            self.send_telegram_message(f"❌ Account '{account_name}' not found!", chat_id)
            return

        if not account.is_active:
            self.send_telegram_message(f"❌ Account '{account_name}' is inactive!", chat_id)
            return

        self.send_telegram_message(f"🔄 Restarting <b>{account_name}</b>...", chat_id)

        if self.perform_restart_cycle_for_account(account):
            account.restart_count += 1
            account.last_restart_time = datetime.now()
            self.send_telegram_message(f"✅ <b>{account_name}</b> restarted successfully!", chat_id)
        else:
            self.send_telegram_message(f"❌ Failed to restart <b>{account_name}</b>!", chat_id)

    def _force_login_account(self, chat_id, account_name):
        account = self._find_account_by_name(account_name)
        if not account:
            self.send_telegram_message(f"❌ Account '{account_name}' not found!", chat_id)
            return

        self.send_telegram_message(f"🔐 Logging into <b>{account_name}</b>...", chat_id)

        if self.perform_complete_login(account):
            self.send_telegram_message(f"✅ <b>{account_name}</b> login successful!", chat_id)
        else:
            self.send_telegram_message(f"❌ <b>{account_name}</b> login failed!", chat_id)

    def _change_restart_time(self, chat_id, account_name, new_time):
        account = self._find_account_by_name(account_name)
        if not account:
            self.send_telegram_message(f"❌ Account '{account_name}' not found!", chat_id)
            return

        if new_time < 5:
            self.send_telegram_message("❌ Restart time must be at least 5 minutes!", chat_id)
            return

        old_time = account.custom_restart_time
        account.custom_restart_time = new_time
        self.save_config()

        message = f"⏰ <b>{account_name}</b>\nRestart time changed:\n{old_time}min → {new_time}min"
        self.send_telegram_message(message, chat_id)

    def _toggle_auto_restart(self, chat_id, account_name, status):
        account = self._find_account_by_name(account_name)
        if not account:
            self.send_telegram_message(f"❌ Account '{account_name}' not found!", chat_id)
            return

        account.auto_restart = status
        self.save_config()
        state = "ON" if status else "OFF"

        message = f"⚙️ <b>{account_name}</b>\nAuto Restart: <b>{state}</b>"
        self.send_telegram_message(message, chat_id)

    def _start_all_servers(self, chat_id):
        self.send_telegram_message("🚀 <b>Starting ALL servers...</b>", chat_id)

        success_count = 0
        active_accounts = [acc for acc in self.accounts if acc.is_active]
        total_active = len(active_accounts)

        for account in active_accounts:
            if self.start_server(account):
                success_count += 1
                account.last_restart_time = datetime.now()
            time.sleep(5)

        message = f"✅ <b>Start Complete!</b>\n\nSuccessful: {success_count}/{total_active}"
        self.send_telegram_message(message, chat_id)

    def _stop_all_servers(self, chat_id):
        self.send_telegram_message("🛑 <b>Stopping ALL servers...</b>", chat_id)

        success_count = 0
        active_accounts = [acc for acc in self.accounts if acc.is_active]
        total_active = len(active_accounts)

        for account in active_accounts:
            if self.stop_server(account):
                success_count += 1
            time.sleep(5)

        message = f"🛑 <b>Stop Complete!</b>\n\nSuccessful: {success_count}/{total_active}"
        self.send_telegram_message(message, chat_id)

    def _send_help_message(self, chat_id):
        message = """
🤖 <b>HELP - PELLA BOT</b>

<b>Usage Examples:</b>
<code>/add_account</code> - Shows add account format
<code>/remove_account Main Account</code>
<code>/restart Main Account</code>
<code>/change_time Main Account 30</code>
<code>/auto_restart Main Account on</code>
<code>/login Main Account</code>
<code>/status</code>

<b>Note:</b> Use exact account names as shown in /accounts
"""
        self.send_telegram_message(message, chat_id)

    def _send_unknown_command(self, chat_id):
        message = "❌ <b>Unknown Command</b>\n\nType /help for available commands"
        self.send_telegram_message(message, chat_id)

    def _find_account_by_name(self, account_name):
        for account in self.accounts:
            if account.account_name.lower() == account_name.lower():
                return account
        return None

    def _send_add_account_instructions(self, chat_id):
        message = """
➕ <b>ADD NEW ACCOUNT</b>

<b>Format:</b>
<code>/add_account AccountName|email@example.com|password|server_id|chat_id|restart_time</code>

<b>Example:</b>
<code>/add_account My Account|user@mail.com|mypass123|abc123xyz|8316636623|45</code>

<b>Parameters:</b>
• <b>AccountName:</b> Unique name for account
• <b>Email:</b> Pella account email
• <b>Password:</b> Pella account password
• <b>Server ID:</b> Your server ID from Pella
• <b>Chat ID:</b> Your Telegram chat ID (optional, use 0 to skip)
• <b>Restart Time:</b> Minutes between restarts (default 45)

<b>Note:</b> Use | as separator between fields
"""
        self.send_telegram_message(message, chat_id)
    
    def _add_new_account(self, chat_id, params):
        try:
            parts = [p.strip() for p in params.split('|')]
            
            if len(parts) < 4:
                self.send_telegram_message("❌ Invalid format! Use /add_account to see instructions.", chat_id)
                return
            
            account_name = parts[0]
            email = parts[1]
            password = parts[2]
            server_id = parts[3]
            telegram_chat_id = parts[4] if len(parts) > 4 and parts[4] != '0' else None
            custom_restart_time = int(parts[5]) if len(parts) > 5 else 45
            
            if self._find_account_by_name(account_name):
                self.send_telegram_message(f"❌ Account '{account_name}' already exists!", chat_id)
                return
            
            new_account = PellaAccount(
                account_name=account_name,
                email=email,
                password=password,
                server_id=server_id,
                telegram_chat_id=telegram_chat_id,
                custom_restart_time=custom_restart_time,
                auto_restart=True,
                is_active=True
            )
            
            self.accounts.append(new_account)
            
            if self.save_config():
                message = f"✅ <b>Account Added Successfully!</b>\n\n"
                message += f"📝 Name: {account_name}\n"
                message += f"📧 Email: {email}\n"
                message += f"🆔 Server ID: {server_id}\n"
                message += f"⏰ Restart Time: {custom_restart_time}min\n"
                self.send_telegram_message(message, chat_id)
            else:
                self.accounts.remove(new_account)
                self.send_telegram_message("❌ Failed to save account!", chat_id)
        
        except Exception as e:
            logging.error(f"❌ Error adding account: {e}")
            self.send_telegram_message(f"❌ Error: {str(e)}", chat_id)
    
    def _remove_account(self, chat_id, account_name):
        account = self._find_account_by_name(account_name)
        if not account:
            self.send_telegram_message(f"❌ Account '{account_name}' not found!", chat_id)
            return
        
        self.accounts.remove(account)
        
        if self.save_config():
            self.send_telegram_message(f"✅ <b>{account_name}</b> removed successfully!", chat_id)
        else:
            self.accounts.append(account)
            self.send_telegram_message("❌ Failed to remove account!", chat_id)

    def send_bot_startup_message(self):
        message = "🤖 <b>PELLA BOT STARTED SUCCESSFULLY!</b>\n\nType /help for all commands"
        self.send_broadcast_message(message)

    def start_smart_scheduler(self):
        import threading
        scheduler_thread = threading.Thread(target=self._scheduler_loop)
        scheduler_thread.daemon = True
        scheduler_thread.start()

    def _scheduler_loop(self):
        while self.bot_running:
            try:
                for account in self.accounts:
                    if account.is_active and account.auto_restart:
                        if self._should_restart_account(account):
                            logging.info(f"🔄 [{account.account_name}] Auto-restarting ({account.custom_restart_time}min)")

                            if self.perform_restart_cycle_for_account(account):
                                account.restart_count += 1
                                account.last_restart_time = datetime.now()

                                message = f"🔄 <b>{account.account_name}</b> auto-restarted!\n⏰ Next restart in {account.custom_restart_time}min"
                                self.send_broadcast_message(message)

                time.sleep(60)

            except Exception as e:
                logging.error(f"❌ Scheduler error: {e}")
                time.sleep(60)

    def _should_restart_account(self, account):
        if not account.last_restart_time:
            return True

        time_diff = datetime.now() - account.last_restart_time
        return time_diff.total_seconds() >= (account.custom_restart_time * 60)

    def run_bot_automation(self):
        logging.info("🤖 STARTING BOT-CONTROLLED AUTOMATION!")

        self.start_telegram_bot()
        self.start_smart_scheduler()

        startup_msg = f"🚀 <b>Bot Started</b>\n⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n📊 Accounts: {len(self.accounts)}"
        self.send_broadcast_message(startup_msg)

        try:
            while self.bot_running:
                time.sleep(10)
        except KeyboardInterrupt:
            logging.info("🛑 Bot stopped by user")
            self.bot_running = False
            shutdown_msg = f"🛑 <b>Bot Stopped</b>\n⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            self.send_broadcast_message(shutdown_msg)

# 🎯 FINAL RUN
if __name__ == "__main__":
    automation = PellaMultiAutomation()
    automation.run_bot_automation()
