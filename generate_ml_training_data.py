import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "ml_training_data.json"


def phishing_samples():
    base = [
        {"label": "phishing", "text": "Urgent: your payroll account is locked. Click here and confirm your password immediately."},
        {"label": "phishing", "text": "Executive request: buy gift cards now and send the codes back in this email."},
        {"label": "phishing", "text": "Your bank session expired. Verify login and card PIN from the attachment."},
        {"label": "phishing", "text": "Invoice overdue. Open the zip file and sign in to release payment."},
        {"label": "phishing", "text": "Mailbox quota exceeded. Re-enter credentials to avoid suspension today."},
        {"label": "phishing", "text": "Security alert from admin: approve MFA push and share the code with support."},
        {"label": "phishing", "text": "Vendor changed banking details. Process wire transfer in the next 10 minutes."},
        {"label": "phishing", "text": "Reset your password using this non-company domain link right now."},
        {"label": "suspicious", "text": "Unexpected message from a vendor asking to review a contract in a shared document."},
        {"label": "suspicious", "text": "External sender asks for confirmation of invoice details with urgency but no attachment."},
        {"label": "suspicious", "text": "Email contains a shortened link and vague context about a document review."},
        {"label": "suspicious", "text": "Request to confirm your phone number through an unfamiliar portal."},
        {"label": "safe", "text": "Reminder: engineering standup moved to 10:30 AM in the normal calendar invite."},
        {"label": "safe", "text": "Your approved internal ticket has been updated in the company helpdesk."},
        {"label": "safe", "text": "Quarterly security training is available on the official company LMS portal."},
        {"label": "safe", "text": "The IT team announced scheduled VPN maintenance in the internal status page."},
    ]
    phishing_templates = [
        "Urgent action required: verify your {asset} password immediately through this link.",
        "Your {asset} will be suspended today unless you confirm your credentials now.",
        "Open the attached document and sign in to release the blocked {asset}.",
        "Finance request: process {action} within 10 minutes and reply confidentially.",
    ]
    suspicious_templates = [
        "Unexpected external message asks you to review a {asset} document in a shared portal.",
        "Sender requests confirmation of {asset} details with mild urgency and vague context.",
        "Message contains a shortened link about a {asset} review with little explanation.",
    ]
    safe_templates = [
        "Internal notice: the {asset} maintenance window is scheduled and documented on the company portal.",
        "Approved support ticket confirms the {asset} update in the official helpdesk.",
        "Security team posted the new {asset} guidance in the internal knowledge base.",
    ]
    assets = ["mailbox", "VPN", "payroll", "HR portal", "invoice system", "SSO account"]
    actions = ["wire transfer", "gift card purchase", "invoice update", "credential reset"]
    for asset in assets:
        for template in phishing_templates:
            base.append({"label": "phishing", "text": template.format(asset=asset, action=actions[0])})
        for template in suspicious_templates:
            base.append({"label": "suspicious", "text": template.format(asset=asset)})
        for template in safe_templates:
            base.append({"label": "safe", "text": template.format(asset=asset)})
    for action in actions:
        base.append({"label": "phishing", "text": phishing_templates[3].format(asset="finance portal", action=action)})
    return base


def log_samples():
    base = [
        {"label": "high", "text": "Failed password for admin from 45.33.12.9 repeated 30 times in 2 minutes followed by Accepted password."},
        {"label": "high", "text": "Web server spawned /bin/sh after POST request containing cmd=cat+/etc/passwd."},
        {"label": "high", "text": "Host began renaming thousands of files and deleting shadow copies."},
        {"label": "high", "text": "Service account downloaded 12GB to rare external destination at 03:14 UTC."},
        {"label": "medium", "text": "Ten failed login attempts for multiple users from one IP over 30 minutes."},
        {"label": "medium", "text": "Burst of DNS TXT requests with long random subdomains to one domain."},
        {"label": "medium", "text": "Application returned repeated SQL syntax errors after crafted query strings."},
        {"label": "medium", "text": "User approved MFA after 9 denied pushes from unfamiliar device."},
        {"label": "low", "text": "One failed login attempt followed by successful login from known office IP."},
        {"label": "low", "text": "Scheduled vulnerability scanner requested multiple HTTP endpoints during maintenance."},
        {"label": "low", "text": "Expected software update downloaded packages from approved repository."},
        {"label": "low", "text": "Routine backup process transferred encrypted archive to approved storage target."},
    ]
    high_patterns = [
        "Accepted password for {user} after {count} failed attempts from {ip}.",
        "New child process /bin/sh created by web service after POST from {ip}.",
        "Mass file encryption observed on {host} with backup deletion.",
    ]
    medium_patterns = [
        "{count} failed logins for many users from {ip} over 20 minutes.",
        "Repeated SQL parser errors after crafted requests from {ip}.",
        "Multiple denied MFA prompts followed by one approval for {user}.",
    ]
    low_patterns = [
        "One failed login for {user} followed by normal success from known IP {ip}.",
        "Approved scanner checked {host} during maintenance.",
        "Normal backup copied archive from {host} to approved target.",
    ]
    users = ["admin", "svc_backup", "finance_user", "vpn_user"]
    ips = ["45.33.12.9", "198.51.100.7", "203.0.113.14", "91.200.12.3"]
    hosts = ["web-01", "db-02", "mail-01", "files-01"]
    counts = ["12", "18", "30", "55"]
    for user in users:
        for ip in ips[:2]:
            for count in counts[:2]:
                base.append({"label": "high", "text": high_patterns[0].format(user=user, count=count, ip=ip)})
                base.append({"label": "medium", "text": medium_patterns[0].format(count=count, ip=ip)})
                base.append({"label": "low", "text": low_patterns[0].format(user=user, ip=ip)})
    for host in hosts:
        base.append({"label": "high", "text": high_patterns[2].format(host=host)})
        base.append({"label": "low", "text": low_patterns[1].format(host=host)})
        base.append({"label": "low", "text": low_patterns[2].format(host=host)})
    return base


def attack_samples():
    base = [
        {"label": "sql_injection", "text": "Request contains union select and quote-heavy payload to login form."},
        {"label": "sql_injection", "text": "Input uses OR 1=1 comment syntax to bypass authentication."},
        {"label": "xss", "text": "Comment field stores script tag and triggers alert on page view."},
        {"label": "xss", "text": "Reflected parameter injects javascript event handler into HTML response."},
        {"label": "phishing", "text": "Email asks user to confirm password and open urgent attachment."},
        {"label": "phishing", "text": "Spoofed sender requests gift cards and confidential reply."},
        {"label": "brute_force", "text": "Many repeated password failures from same source against one account."},
        {"label": "brute_force", "text": "Password spray attempts common password across hundreds of usernames."},
        {"label": "ransomware", "text": "Files renamed rapidly, ransom note dropped, backups disabled."},
        {"label": "ransomware", "text": "Mass encryption behavior with shadow copy deletion detected."},
        {"label": "ssrf", "text": "Backend requested cloud metadata endpoint from user-supplied URL parameter."},
        {"label": "ssrf", "text": "Image fetch feature caused server to connect to internal IP range."},
        {"label": "command_injection", "text": "Shell metacharacters in hostname input caused ping command execution."},
        {"label": "command_injection", "text": "User input passed to sh -c with semicolon and curl payload."},
        {"label": "credential_stuffing", "text": "Same IP attempts breached email-password combos across many accounts."},
        {"label": "credential_stuffing", "text": "Low success rate after large cross-account login attempt burst."},
    ]
    templates = {
        "sql_injection": [
            "Request injects UNION SELECT into {surface}.",
            "Input uses quote and OR 1=1 to bypass {surface}.",
        ],
        "xss": [
            "Stored comment on {surface} contains script tag and browser callback.",
            "Reflected parameter on {surface} injects event handler into HTML.",
        ],
        "phishing": [
            "Message about {surface} asks user to verify password immediately.",
            "Spoofed sender pressures victim to open attachment for {surface}.",
        ],
        "brute_force": [
            "Repeated password failures target {surface} from one source.",
            "Common password sprayed against many {surface} accounts.",
        ],
        "ransomware": [
            "{surface} shows mass encryption and ransom note creation.",
            "{surface} deletes backups before rapid file renames.",
        ],
        "ssrf": [
            "{surface} fetch feature requested cloud metadata endpoint.",
            "{surface} caused backend connection to internal IP address.",
        ],
        "command_injection": [
            "{surface} input included semicolon and shell command.",
            "{surface} passed user value into sh -c execution path.",
        ],
        "credential_stuffing": [
            "Large login burst reuses leaked credentials against {surface}.",
            "Many accounts on {surface} see low-success login attempts from one IP.",
        ],
    }
    surfaces = ["login form", "search endpoint", "comment box", "image fetcher", "admin panel", "VPN portal"]
    for label, patterns in templates.items():
        for surface in surfaces:
            for pattern in patterns:
                base.append({"label": label, "text": pattern.format(surface=surface)})
    return base


def code_samples():
    base = [
        {"label": "insecure", "text": "query = f\"SELECT * FROM users WHERE id = '{user_id}'\""},
        {"label": "insecure", "text": "el.innerHTML = userComment"},
        {"label": "insecure", "text": "os.system('ping ' + host)"},
        {"label": "insecure", "text": "password = 'supersecret'"},
        {"label": "insecure", "text": "obj = pickle.loads(data)"},
        {"label": "insecure", "text": "return redirect(request.args['next'])"},
        {"label": "secure", "text": "cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))"},
        {"label": "secure", "text": "el.textContent = userComment"},
        {"label": "secure", "text": "subprocess.run(['ping', host], check=True)"},
        {"label": "secure", "text": "password = os.environ['DB_PASSWORD']"},
        {"label": "secure", "text": "obj = json.loads(data)"},
        {"label": "secure", "text": "return redirect(validate_relative_path(request.args.get('next')))"},
    ]
    insecure_patterns = [
        "cursor.execute(\"SELECT * FROM users WHERE email = '\" + email + \"'\")",
        "response.write(request.getParameter(\"q\"))",
        "system('ping ' + host)",
        "secret = 'prod-token'",
        "unserialize($_POST['data'])",
    ]
    secure_patterns = [
        "cursor.execute(\"SELECT * FROM users WHERE email = %s\", (email,))",
        "element.textContent = query",
        "subprocess.run(['ping', host], check=True)",
        "secret = os.environ['TOKEN']",
        "json.loads(request_body)",
    ]
    for text in insecure_patterns:
        base.append({"label": "insecure", "text": text})
    for text in secure_patterns:
        base.append({"label": "secure", "text": text})
    return base


def main():
    data = {
        "phishing_email": phishing_samples(),
        "log_threat": log_samples(),
        "attack_category": attack_samples(),
        "code_security": code_samples(),
    }
    OUTPUT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"Wrote training data to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
