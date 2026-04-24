import os
import base64
import hashlib
import json
import time
import re
import requests
import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import msal

# ── Configuration ───────────────────────────────────────────

CLIENT_ID = "your-azure-app-client-id"
CLIENT_SECRET = "your-azure-app-client-secret"
TENANT_ID = "consumers"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["https://graph.microsoft.com/Mail.Read"]
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"

VIRUSTOTAL_API_KEY = "your-virustotal-api-key"
ABUSEIPDB_API_KEY = "your-abuseipdb-api-key"

STORAGE_PATH = "/path/to/your/analysis/folder"
REPORT_EMAIL = "your-report-recipient@email.com"
SENDER_EMAIL = "your-hotmail@hotmail.com"
SENDER_APP_PASSWORD = "your-app-password"

os.makedirs(STORAGE_PATH, exist_ok=True)
os.makedirs(os.path.join(STORAGE_PATH, "attachments"), exist_ok=True)

# ── Token Manager ───────────────────────────────────────────

class TokenManager:
    """
    Handles Microsoft token acquisition and automatic
    refresh before expiry — keeps long running sessions
    alive without manual intervention
    """

    TOKEN_CACHE_PATH = os.path.join(
        os.path.dirname(__file__), "token_cache.json"
    )

    def __init__(self):
        self._token = None
        self._expiry = None
        self._lock = threading.Lock()
        self._cache = msal.SerializableTokenCache()
        self._load_cache()
        self._app = self._build_app()

    def _load_cache(self):
        """Load persisted token cache from disk"""
        if os.path.exists(self.TOKEN_CACHE_PATH):
            with open(self.TOKEN_CACHE_PATH, 'r') as f:
                self._cache.deserialize(f.read())
            print("[+] Token cache loaded from disk")

    def _save_cache(self):
        """Persist token cache to disk if changed"""
        if self._cache.has_state_changed:
            with open(self.TOKEN_CACHE_PATH, 'w') as f:
                f.write(self._cache.serialize())

    def _build_app(self):
        return msal.PublicClientApplication(
            CLIENT_ID,
            authority=AUTHORITY,
            token_cache=self._cache
        )

    def _acquire_token(self):
        """Try silent first then fall back to interactive"""
        accounts = self._app.get_accounts()

        if accounts:
            result = self._app.acquire_token_silent(
                SCOPES,
                account=accounts[0]
            )
            if result and "access_token" in result:
                print("[+] Token refreshed silently")
                return result

        # Interactive login required
        print("[*] Interactive login required — opening browser")
        result = self._app.acquire_token_interactive(scopes=SCOPES)

        if "access_token" not in result:
            raise Exception(
                f"Authentication failed: {result.get('error_description')}"
            )

        print("[+] Interactive login successful")
        return result

    def get_token(self):
        """
        Return a valid access token — refreshes automatically
        if within 5 minutes of expiry or already expired
        """
        with self._lock:
            now = datetime.utcnow()
            refresh_threshold = timedelta(minutes=5)

            needs_refresh = (
                self._token is None or
                self._expiry is None or
                now >= self._expiry - refresh_threshold
            )

            if needs_refresh:
                result = self._acquire_token()
                self._token = result["access_token"]

                # Microsoft tokens expire in 3600s by default
                expires_in = result.get("expires_in", 3600)
                self._expiry = now + timedelta(seconds=expires_in)

                self._save_cache()

                print(
                    f"[+] Token valid until: "
                    f"{self._expiry.strftime('%Y-%m-%d %H:%M:%S')} UTC"
                )

            return self._token

    def start_background_refresh(self):
        """
        Background thread that proactively refreshes token
        before expiry — prevents any mid-session failures
        """
        def refresh_loop():
            while True:
                try:
                    now = datetime.utcnow()

                    if self._expiry:
                        time_until_expiry = (
                            self._expiry - now
                        ).total_seconds()

                        # Refresh when 10 minutes remain
                        sleep_duration = max(
                            time_until_expiry - 600, 60
                        )
                    else:
                        sleep_duration = 60

                    time.sleep(sleep_duration)

                    # Force refresh
                    with self._lock:
                        self._token = None

                    self.get_token()

                except Exception as e:
                    print(f"[-] Background token refresh error: {e}")
                    time.sleep(60)

        thread = threading.Thread(
            target=refresh_loop,
            daemon=True,
            name="TokenRefresher"
        )
        thread.start()
        print("[*] Background token refresh started")

# ── Deduplication State ─────────────────────────────────────

SEEN_HASHES = set()
SEEN_IPS = set()
SEEN_DOMAINS = set()
SEEN_URLS = set()
SEEN_SENDERS = set()
DEDUP_LOG_PATH = os.path.join(STORAGE_PATH, "dedup_state.json")

def load_dedup_state():
    global SEEN_HASHES, SEEN_IPS, SEEN_DOMAINS, SEEN_URLS, SEEN_SENDERS
    if os.path.exists(DEDUP_LOG_PATH):
        with open(DEDUP_LOG_PATH, 'r') as f:
            state = json.load(f)
            SEEN_HASHES = set(state.get('hashes', []))
            SEEN_IPS = set(state.get('ips', []))
            SEEN_DOMAINS = set(state.get('domains', []))
            SEEN_URLS = set(state.get('urls', []))
            SEEN_SENDERS = set(state.get('senders', []))
        print(
            f"[+] Dedup state loaded — "
            f"{len(SEEN_HASHES)} hashes, "
            f"{len(SEEN_IPS)} IPs, "
            f"{len(SEEN_DOMAINS)} domains known"
        )

def save_dedup_state():
    state = {
        'hashes': list(SEEN_HASHES),
        'ips': list(SEEN_IPS),
        'domains': list(SEEN_DOMAINS),
        'urls': list(SEEN_URLS),
        'senders': list(SEEN_SENDERS)
    }
    with open(DEDUP_LOG_PATH, 'w') as f:
        json.dump(state, f, indent=2)

def is_duplicate_email(sender, sender_ip, domain):
    return (
        sender in SEEN_SENDERS and
        sender_ip in SEEN_IPS and
        domain in SEEN_DOMAINS
    )

def is_duplicate_hash(sha256):
    return sha256 in SEEN_HASHES

def is_duplicate_url(url):
    return url in SEEN_URLS

def register_indicators(sender, sender_ip, domain, hashes, urls):
    SEEN_SENDERS.add(sender)
    if sender_ip:
        SEEN_IPS.add(sender_ip)
    if domain:
        SEEN_DOMAINS.add(domain)
    SEEN_HASHES.update(hashes)
    SEEN_URLS.update(urls)
    save_dedup_state()

# Daily accumulators
daily_report_data = []
daily_skipped_count = 0

# ── Graph API Helpers ───────────────────────────────────────

def graph_get(token_manager, endpoint, params=None):
    headers = {"Authorization": f"Bearer {token_manager.get_token()}"}
    response = requests.get(
        f"{GRAPH_ENDPOINT}{endpoint}",
        headers=headers,
        params=params,
        timeout=15
    )
    if response.status_code == 200:
        return response.json()
    if response.status_code == 401:
        # Force token refresh on auth failure
        print("[!] 401 received — forcing token refresh")
        with token_manager._lock:
            token_manager._token = None
        headers["Authorization"] = (
            f"Bearer {token_manager.get_token()}"
        )
        retry = requests.get(
            f"{GRAPH_ENDPOINT}{endpoint}",
            headers=headers,
            params=params,
            timeout=15
        )
        if retry.status_code == 200:
            return retry.json()
    return None

def graph_get_bytes(token_manager, endpoint):
    headers = {"Authorization": f"Bearer {token_manager.get_token()}"}
    response = requests.get(
        f"{GRAPH_ENDPOINT}{endpoint}",
        headers=headers,
        timeout=15
    )
    if response.status_code == 200:
        return response.content
    return None

# ── Email Parsing ───────────────────────────────────────────

def extract_sender_ip(internet_message_headers):
    if not internet_message_headers:
        return None
    for header in internet_message_headers:
        if header.get('name', '').lower() == 'received':
            ip_match = re.search(
                r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]',
                header.get('value', '')
            )
            if ip_match:
                ip = ip_match.group(1)
                if not ip.startswith(('10.', '192.168.', '172.', '127.')):
                    return ip
    return None

def extract_urls(text):
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|'
        r'(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return list(set(url_pattern.findall(text)))

def extract_domain(email_address):
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1) if match else None

# ── API Lookups ─────────────────────────────────────────────

def virustotal_hash_lookup(sha256):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "found": True,
                "malicious_count": stats.get('malicious', 0),
                "total_engines": sum(stats.values()),
                "threat_label": data['data']['attributes']
                    .get('popular_threat_classification', {})
                    .get('suggested_threat_label', 'Unknown')
            }
        elif response.status_code == 404:
            return {"found": False}
    except Exception as e:
        print(f"[-] VT hash error: {e}")
    return {"found": False}

def virustotal_url_lookup(url_to_check):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url_to_check},
            timeout=10
        )
        if response.status_code == 200:
            url_id = response.json()['data']['id']
            analysis = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{url_id}",
                headers=headers,
                timeout=10
            ).json()
            stats = analysis['data']['attributes']['stats']
            return {
                "found": True,
                "malicious": stats.get('malicious', 0),
                "total": sum(stats.values())
            }
    except Exception as e:
        print(f"[-] VT URL error: {e}")
    return {"found": False}

def abuseipdb_lookup(ip):
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()['data']
            return {
                "country": data.get('countryCode', 'Unknown'),
                "abuse_score": data.get('abuseConfidenceScore', 0),
                "total_reports": data.get('totalReports', 0),
                "isp": data.get('isp', 'Unknown')
            }
    except Exception as e:
        print(f"[-] AbuseIPDB error: {e}")
    return None

def mxtoolbox_lookup(domain):
    try:
        response = requests.get(
            f"https://mxtoolbox.com/api/v1/lookup/mx/{domain}",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "found": True,
                "mx_records": [
                    r.get('Name', '')
                    for r in data.get('Information', [])
                ],
                "failed_checks": data.get('Failed', []),
                "warnings": data.get('Warnings', [])
            }
    except Exception as e:
        print(f"[-] MXToolbox error: {e}")
    return {"found": False}

def spamhaus_lookup(ip):
    import socket
    reversed_ip = '.'.join(reversed(ip.split('.')))
    try:
        result = socket.gethostbyname(
            f"{reversed_ip}.zen.spamhaus.org"
        )
        codes = {
            "127.0.0.2": "SBL - Spamhaus Block List",
            "127.0.0.3": "SBL CSS - Snowshoe spam",
            "127.0.0.4": "XBL - Exploits Block List",
            "127.0.0.9": "SBL DROP - Do Not Route",
            "127.0.0.10": "PBL ISP - Policy Block List",
            "127.0.0.11": "PBL Spamhaus"
        }
        return {
            "listed": True,
            "list": codes.get(result, f"Listed — code {result}")
        }
    except:
        return {"listed": False}

# ── Main Email Processor ────────────────────────────────────

def process_email(token_manager, message):
    global daily_skipped_count

    message_id = message['id']
    subject = message.get('subject', '')
    from_field = message.get('from', {}).get('emailAddress', {})
    from_address = from_field.get('address', '')
    from_name = from_field.get('name', '')

    reply_to_list = message.get('replyTo', [])
    reply_to_address = (
        reply_to_list[0].get('emailAddress', {}).get('address', '')
        if reply_to_list else ''
    )

    full_message = graph_get(
        token_manager,
        f"/me/messages/{message_id}",
        params={"$select": "internetMessageHeaders,body,subject"}
    )

    headers = (
        full_message.get('internetMessageHeaders', [])
        if full_message else []
    )
    body_content = (
        full_message.get('body', {}).get('content', '')
        if full_message else ''
    )

    sender_ip = extract_sender_ip(headers)
    sender_domain = extract_domain(from_address)
    embedded_urls = extract_urls(body_content)

    spoofing_detected = (
        from_address and reply_to_address and
        from_address.lower() != reply_to_address.lower()
    )

    if is_duplicate_email(from_address, sender_ip, sender_domain):
        print(f"[~] Duplicate campaign skipped: {from_address}")
        daily_skipped_count += 1
        return

    new_urls = [u for u in embedded_urls if not is_duplicate_url(u)]
    repeated_urls = [u for u in embedded_urls if is_duplicate_url(u)]

    print(f"\n[+] New email: {from_address} — {subject}")

    ip_data = None
    spamhaus_data = None
    if sender_ip and sender_ip not in SEEN_IPS:
        ip_data = abuseipdb_lookup(sender_ip)
        spamhaus_data = spamhaus_lookup(sender_ip)

    domain_data = None
    if sender_domain and sender_domain not in SEEN_DOMAINS:
        domain_data = mxtoolbox_lookup(sender_domain)

    url_results = {}
    for url in new_urls[:5]:
        url_results[url] = virustotal_url_lookup(url)
        time.sleep(15)

    attachments = []
    new_hashes = []

    att_response = graph_get(
        token_manager,
        f"/me/messages/{message_id}/attachments"
    )

    if att_response and att_response.get('value'):
        for att in att_response['value']:
            filename = att.get('name', 'unknown')

            if att.get('@odata.type') == '#microsoft.graph.fileAttachment':
                content_bytes = base64.b64decode(
                    att.get('contentBytes', '')
                )
            else:
                content_bytes = graph_get_bytes(
                    token_manager,
                    f"/me/messages/{message_id}/attachments/{att['id']}/$value"
                )

            if not content_bytes:
                continue

            sha256 = hashlib.sha256(content_bytes).hexdigest()

            if is_duplicate_hash(sha256):
                print(f"    [~] Duplicate attachment skipped: {filename}")
                attachments.append({
                    "filename": filename,
                    "sha256": sha256,
                    "duplicate": True,
                    "virustotal": {"found": False}
                })
                continue

            safe_name = f"{sha256}_{filename}"
            filepath = os.path.join(
                STORAGE_PATH, "attachments", safe_name
            )
            with open(filepath, 'wb') as f:
                f.write(content_bytes)

            time.sleep(15)
            vt_result = virustotal_hash_lookup(sha256)
            new_hashes.append(sha256)

            attachments.append({
                "filename": filename,
                "sha256": sha256,
                "duplicate": False,
                "virustotal": vt_result
            })
            print(f"    [+] Saved: {safe_name}")

    register_indicators(
        from_address, sender_ip, sender_domain,
        new_hashes, new_urls
    )

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "from_address": from_address,
        "from_name": from_name,
        "reply_to": reply_to_address,
        "subject": subject,
        "spoofing_detected": spoofing_detected,
        "sender_ip": sender_ip,
        "sender_domain": sender_domain,
        "ip_reputation": ip_data,
        "spamhaus": spamhaus_data,
        "domain_reputation": domain_data,
        "embedded_urls": new_urls,
        "repeated_urls": repeated_urls,
        "url_vt_results": url_results,
        "attachments": attachments
    }

    daily_report_data.append(entry)

    log_path = os.path.join(STORAGE_PATH, "capture_log.json")
    with open(log_path, 'a') as log:
        log.write(json.dumps(entry) + "\n")

# ── Junk Folder Poller ──────────────────────────────────────

def poll_junk_folder(token_manager):
    last_checked = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[*] Polling Junk folder — started at {last_checked}")

    while True:
        try:
            result = graph_get(
                token_manager,
                "/me/mailFolders/junkemail/messages",
                params={
                    "$filter": f"receivedDateTime ge {last_checked}",
                    "$select": (
                        "id,subject,from,replyTo,"
                        "receivedDateTime,hasAttachments"
                    ),
                    "$orderby": "receivedDateTime desc",
                    "$top": 25
                }
            )

            if result and result.get('value'):
                messages = result['value']
                print(f"[+] {len(messages)} new junk email(s) found")
                for message in messages:
                    process_email(token_manager, message)
                last_checked = datetime.utcnow().strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )

        except Exception as e:
            print(f"[-] Poll error: {e}")

        time.sleep(300)

# ── Report Generator ────────────────────────────────────────

def generate_report():
    global daily_skipped_count

    if not daily_report_data and daily_skipped_count == 0:
        return None

    today = datetime.now().strftime("%Y-%m-%d")
    report = f"""
HONEYPOT DAILY REPORT — {today}
{'=' * 60}
New unique emails processed:  {len(daily_report_data)}
Duplicate campaigns skipped:  {daily_skipped_count}
"""
    for i, entry in enumerate(daily_report_data, 1):
        report += f"""
{'─' * 60}
EMAIL #{i}
{'─' * 60}
Timestamp:        {entry['timestamp']}
From Name:        {entry['from_name']}
From Address:     {entry['from_address']}
Reply-To:         {entry['reply_to'] or 'Not set'}
Subject:          {entry['subject']}
Sender IP:        {entry['sender_ip'] or 'Not extracted'}
Sender Domain:    {entry['sender_domain'] or 'Unknown'}

SPOOFING ANALYSIS
─────────────────
{'⚠ SPOOFING DETECTED — From address differs from Reply-To'
  if entry['spoofing_detected']
  else '✓ No spoofing detected'}

IP REPUTATION
─────────────
"""
        if entry['ip_reputation']:
            ip = entry['ip_reputation']
            report += (
                f"Country:          {ip['country']}\n"
                f"ISP:              {ip['isp']}\n"
                f"Abuse Score:      {ip['abuse_score']}/100\n"
                f"Total Reports:    {ip['total_reports']}\n"
            )
        else:
            report += "Previously seen IP — skipped re-query\n"

        report += "\nSPAMHAUS\n────────\n"
        if entry['spamhaus']:
            sh = entry['spamhaus']
            report += (
                f"{'⚠ LISTED: ' + sh['list'] if sh['listed'] else '✓ Not listed'}\n"
            )
        else:
            report += "Previously seen IP — skipped re-query\n"

        report += "\nDOMAIN REPUTATION\n─────────────────\n"
        if entry['domain_reputation'] and entry['domain_reputation']['found']:
            dr = entry['domain_reputation']
            report += (
                f"MX Records:       {', '.join(dr['mx_records']) or 'None'}\n"
                f"Failed Checks:    {len(dr['failed_checks'])}\n"
                f"Warnings:         {len(dr['warnings'])}\n"
            )
        else:
            report += "Previously seen domain — skipped re-query\n"

        report += "\nEMBEDDED URLs\n─────────────\n"
        if entry['embedded_urls']:
            report += "New URLs:\n"
            for url in entry['embedded_urls']:
                vt = entry['url_vt_results'].get(url, {})
                vt_status = (
                    f"⚠ Malicious ({vt['malicious']}/{vt['total']})"
                    if vt.get('malicious', 0) > 0
                    else "✓ Clean"
                ) if vt.get('found') else "Not in VT database"
                report += f"  {url}\n  VT: {vt_status}\n\n"
        if entry['repeated_urls']:
            report += "Previously seen URLs (not re-queried):\n"
            for url in entry['repeated_urls']:
                report += f"  {url}\n"
        if not entry['embedded_urls'] and not entry['repeated_urls']:
            report += "No embedded URLs found\n"

        report += "\nATTACHMENTS\n───────────\n"
        if entry['attachments']:
            for att in entry['attachments']:
                if att.get('duplicate'):
                    report += (
                        f"Filename:         {att['filename']}\n"
                        f"SHA256:           {att['sha256']}\n"
                        f"Status:           Previously captured — skipped\n\n"
                    )
                else:
                    vt = att['virustotal']
                    vt_status = (
                        f"⚠ MALICIOUS — "
                        f"{vt['malicious_count']}/{vt['total_engines']} "
                        f"engines — {vt['threat_label']}"
                        if vt.get('found') and vt.get('malicious_count', 0) > 0
                        else "✓ Clean or not found in VT"
                    )
                    report += (
                        f"Filename:         {att['filename']}\n"
                        f"SHA256:           {att['sha256']}\n"
                        f"VirusTotal:       {vt_status}\n\n"
                    )
        else:
            report += "No attachments\n"

    report += f"\n{'=' * 60}\nEnd of report — {today}\n"
    return report

def send_report():
    global daily_skipped_count
    report_body = generate_report()

    if not report_body:
        print("[~] No activity to report today")
        return

    today = datetime.now().strftime("%Y-%m-%d")
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = REPORT_EMAIL
    msg['Subject'] = f"Honeypot Daily Report — {today}"
    msg.attach(MIMEText(report_body, 'plain'))

    try:
        with smtplib.SMTP('smtp-mail.outlook.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)
        print(f"[+] Report sent to {REPORT_EMAIL}")
    except Exception as e:
        print(f"[-] Failed to send report: {e}")

    daily_report_data.clear()
    daily_skipped_count = 0

# ── Daily Scheduler ─────────────────────────────────────────

def schedule_daily_report():
    def report_loop():
        while True:
            now = datetime.now()
            seconds_until_midnight = (
                (24 - now.hour - 1) * 3600 +
                (60 - now.minute - 1) * 60 +
                (60 - now.second)
            )
            time.sleep(seconds_until_midnight)
            send_report()

    thread = threading.Thread(
        target=report_loop,
        daemon=True,
        name="ReportScheduler"
    )
    thread.start()
    print("[*] Daily report scheduled for midnight")

# ── Entry Point ─────────────────────────────────────────────

if __name__ == '__main__':
    load_dedup_state()
    token_manager = TokenManager()
    token_manager.get_token()
    token_manager.start_background_refresh()
    schedule_daily_report()
    poll_junk_folder(token_manager)
