import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
OUTPUT_PATH = BASE_DIR / "data" / "code_fix_pairs.json"


VULNERABILITIES = [
    {
        "slug": "sql-injection",
        "title": "SQL Injection",
        "category": "application-security",
        "languages": [
            (
                "python",
                "query = f\"SELECT * FROM users WHERE id = '{user_id}'\"",
                "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
            ),
            (
                "php",
                "$sql = \"SELECT * FROM users WHERE email = '\" . $_POST['email'] . \"'\";",
                "$stmt = $pdo->prepare(\"SELECT * FROM users WHERE email = ?\"); $stmt->execute([$_POST['email']]);",
            ),
            (
                "node",
                "const sql = `SELECT * FROM users WHERE name = '${name}'`;",
                "db.query('SELECT * FROM users WHERE name = ?', [name]);",
            ),
            (
                "java",
                "String q = \"SELECT * FROM users WHERE id='\" + id + \"'\";",
                "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\");",
            ),
            (
                "go",
                "db.Query(\"SELECT * FROM users WHERE email='\" + email + \"'\")",
                "db.Query(\"SELECT * FROM users WHERE email = ?\", email)",
            ),
            (
                "ruby",
                "User.where(\"email = '#{email}'\")",
                "User.where(email: email)",
            ),
            (
                "csharp",
                "var sql = $\"SELECT * FROM Users WHERE Id = '{id}'\";",
                "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = @id\", conn);",
            ),
            (
                "rust",
                "let q = format!(\"SELECT * FROM users WHERE id = '{}'\", user_id);",
                "sqlx::query(\"SELECT * FROM users WHERE id = ?\").bind(user_id);",
            ),
            (
                "perl",
                "$dbh->do(\"SELECT * FROM users WHERE name = '$name'\");",
                "$sth = $dbh->prepare('SELECT * FROM users WHERE name = ?'); $sth->execute($name);",
            ),
            (
                "scala",
                "val q = s\"SELECT * FROM users WHERE id = '$id'\"",
                "sql\"SELECT * FROM users WHERE id = $id\".as(...)",
            ),
        ],
        "explanation": "Direct string interpolation in SQL lets attacker-controlled input alter query structure. Use parameterized statements and least-privilege database accounts.",
    },
    {
        "slug": "xss",
        "title": "Cross-Site Scripting",
        "category": "application-security",
        "languages": [
            ("javascript", "el.innerHTML = userComment;", "el.textContent = userComment;"),
            ("php", "echo $_GET['name'];", "echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');"),
            ("python", "return f'<div>{comment}</div>'", "return render_template('view.html', comment=comment)"),
            ("java", "out.println(request.getParameter(\"q\"));", "out.println(StringEscapeUtils.escapeHtml4(request.getParameter(\"q\")));"),
            ("ruby", "<%= raw params[:message] %>", "<%= params[:message] %>"),
            ("go", "fmt.Fprintf(w, userInput)", "template.HTMLEscape(w, []byte(userInput))"),
            ("csharp", "@Html.Raw(Model.Comment)", "@Model.Comment"),
            ("vue", "<div v-html=\"message\"></div>", "<div>{{ message }}</div>"),
            ("react", "<div dangerouslySetInnerHTML={{__html: html}} />", "<div>{text}</div>"),
            ("django", "{{ comment|safe }}", "{{ comment }}"),
        ],
        "explanation": "Rendering untrusted content as HTML or script allows arbitrary browser-side code execution. Prefer contextual output encoding and safe DOM APIs.",
    },
    {
        "slug": "command-injection",
        "title": "Command Injection",
        "category": "application-security",
        "languages": [
            ("python", "os.system('ping ' + host)", "subprocess.run(['ping', host], check=True)"),
            ("php", "system('nslookup ' . $_GET['host']);", "$host = escapeshellarg($_GET['host']); system(\"nslookup $host\");"),
            ("node", "exec('ping ' + host)", "execFile('ping', [host])"),
            ("ruby", "system(\"ping #{host}\")", "system('ping', host)"),
            ("perl", "system(\"ping $host\")", "system('ping', $host)"),
            ("go", "exec.Command(\"sh\", \"-c\", \"ping \"+host).Run()", "exec.Command(\"ping\", host).Run()"),
            ("java", "Runtime.getRuntime().exec(\"ping \" + host);", "new ProcessBuilder(\"ping\", host).start();"),
            ("csharp", "Process.Start(\"cmd.exe\", \"/c ping \" + host);", "Process.Start(new ProcessStartInfo(\"ping\", host));"),
            ("rust", "Command::new(\"sh\").arg(\"-c\").arg(format!(\"ping {}\", host)).status();", "Command::new(\"ping\").arg(host).status();"),
            ("bash", "eval \"ping $HOST\"", "ping -- \"$HOST\""),
        ],
        "explanation": "Concatenating user input into shell commands can execute arbitrary OS commands. Avoid shells and pass arguments as separate values.",
    },
    {
        "slug": "path-traversal",
        "title": "Path Traversal",
        "category": "application-security",
        "languages": [
            ("python", "open('/var/data/' + filename)", "open((BASE_DIR / Path(filename).name))"),
            ("php", "readfile('/srv/files/' . $_GET['file']);", "$name = basename($_GET['file']); readfile('/srv/files/' . $name);"),
            ("node", "fs.readFileSync('/srv/files/' + file)", "fs.readFileSync(path.join(BASE, path.basename(file)))"),
            ("java", "Paths.get(base + file)", "Paths.get(base).resolve(Paths.get(file).getFileName())"),
            ("go", "os.ReadFile(\"/srv/files/\" + name)", "os.ReadFile(filepath.Join(base, filepath.Base(name)))"),
            ("ruby", "File.read('/srv/files/' + params[:f])", "File.read(File.join(BASE, File.basename(params[:f])))"),
            ("csharp", "File.ReadAllText(baseDir + file)", "File.ReadAllText(Path.Combine(baseDir, Path.GetFileName(file)))"),
            ("rust", "fs::read_to_string(format!(\"/srv/files/{}\", file))", "fs::read_to_string(base.join(Path::new(file).file_name().unwrap()))"),
            ("perl", "open my $fh, '<', \"/srv/files/$file\";", "use File::Basename; open my $fh, '<', '/srv/files/' . basename($file);"),
            ("scala", "Source.fromFile(base + name)", "Source.fromFile(Paths.get(base, Paths.get(name).getFileName.toString).toFile)"),
        ],
        "explanation": "Joining untrusted file names directly into paths can expose arbitrary filesystem locations. Restrict to approved directories and normalize names.",
    },
    {
        "slug": "hardcoded-secrets",
        "title": "Hardcoded Secrets",
        "category": "secrets-management",
        "languages": [
            ("python", "API_KEY = 'prod-secret-key'", "API_KEY = os.environ['API_KEY']"),
            ("node", "const token = 'ghp_example';", "const token = process.env.GITHUB_TOKEN;"),
            ("php", "$dbPass = 'supersecret';", "$dbPass = getenv('DB_PASSWORD');"),
            ("java", "String secret = \"aws-secret\";", "String secret = System.getenv(\"AWS_SECRET_ACCESS_KEY\");"),
            ("go", "password := \"rootpass\"", "password := os.Getenv(\"DB_PASSWORD\")"),
            ("ruby", "SECRET = 'app-secret'", "SECRET = ENV.fetch('APP_SECRET')"),
            ("csharp", "var key = \"secret\";", "var key = Environment.GetEnvironmentVariable(\"APP_KEY\");"),
            ("rust", "let key = \"secret\";", "let key = std::env::var(\"APP_KEY\")?;"),
            ("bash", "export API_KEY=hardcoded", "export API_KEY=\"$APP_API_KEY\""),
            ("kotlin", "val secret = \"token\"", "val secret = System.getenv(\"TOKEN\")"),
        ],
        "explanation": "Hardcoded credentials leak through repos, logs, and builds. Read secrets from environment variables or a dedicated secret manager.",
    },
    {
        "slug": "csrf",
        "title": "CSRF",
        "category": "web-security",
        "languages": [
            ("django", "<form method='post'>...</form>", "<form method='post'>{% csrf_token %}...</form>"),
            ("flask", "<form method='post'>...</form>", "<form method='post'>{{ form.csrf_token }}...</form>"),
            ("rails", "<form action='/transfer' method='post'>", "<%= form_with url: '/transfer' do |f| %>"),
            ("express", "app.post('/pay', payHandler)", "app.use(csrf()); app.post('/pay', payHandler)"),
            ("php", "if ($_SERVER['REQUEST_METHOD']==='POST') transfer();", "verify_csrf($_POST['csrf']); transfer();"),
            ("spring", "http.csrf().disable();", "http.csrf(Customizer.withDefaults());"),
            ("laravel", "<form method='POST'>", "<form method='POST'>@csrf"),
            ("aspnet", "<form method='post'>", "<form method='post'>@Html.AntiForgeryToken()"),
            ("nextjs", "fetch('/api/update', {method:'POST'})", "fetch('/api/update', {method:'POST', headers:{'X-CSRF-Token': token}})"),
            ("go", "http.HandleFunc('/save', save)", "csrf.Protect(key)(mux)"),
        ],
        "explanation": "State-changing requests without CSRF defenses can be triggered from attacker-controlled sites. Use CSRF tokens and cookie protections.",
    },
    {
        "slug": "open-redirect",
        "title": "Open Redirect",
        "category": "web-security",
        "languages": [
            ("python", "return redirect(request.args['next'])", "return redirect(validate_relative_path(request.args.get('next')))"),
            ("php", "header('Location: ' . $_GET['next']);", "header('Location: ' . safe_redirect($_GET['next']));"),
            ("node", "res.redirect(req.query.next)", "res.redirect(validateRelativePath(req.query.next))"),
            ("java", "response.sendRedirect(request.getParameter(\"next\"));", "response.sendRedirect(safeRelativePath(request.getParameter(\"next\")));"),
            ("ruby", "redirect_to params[:next]", "redirect_to safe_relative_path(params[:next])"),
            ("go", "http.Redirect(w, r, r.URL.Query().Get(\"next\"), 302)", "http.Redirect(w, r, safeRelativePath(r.URL.Query().Get(\"next\")), 302)"),
            ("csharp", "return Redirect(next);", "return LocalRedirect(next);"),
            ("rust", "Redirect::to(next)", "Redirect::to(validate_relative(next))"),
            ("kotlin", "return \"redirect:\" + next", "return \"redirect:\" + safeRelativePath(next)"),
            ("scala", "Redirect(next)", "Redirect(safeRelative(next))"),
        ],
        "explanation": "Redirecting to unvalidated destinations enables phishing and token leakage. Restrict redirects to local relative paths or allowlisted hosts.",
    },
    {
        "slug": "weak-password-storage",
        "title": "Weak Password Storage",
        "category": "identity-security",
        "languages": [
            ("python", "hashed = hashlib.md5(password.encode()).hexdigest()", "hashed = argon2_hasher.hash(password)"),
            ("php", "$hash = md5($password);", "$hash = password_hash($password, PASSWORD_ARGON2ID);"),
            ("node", "const hash = crypto.createHash('sha1').update(password).digest('hex')", "const hash = await argon2.hash(password)"),
            ("java", "String hash = DigestUtils.md5Hex(password);", "String hash = BCrypt.hashpw(password, BCrypt.gensalt());"),
            ("go", "sum := md5.Sum([]byte(password))", "hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)"),
            ("ruby", "Digest::SHA1.hexdigest(password)", "BCrypt::Password.create(password)"),
            ("csharp", "var hash = SHA1.HashData(bytes);", "var hash = BCrypt.Net.BCrypt.HashPassword(password);"),
            ("rust", "let hash = format!(\"{:x}\", md5::compute(password));", "let hash = argon2::hash_encoded(password.as_bytes(), salt, &config)?;"),
            ("perl", "$hash = md5_hex($password);", "$hash = Authen::Passphrase::BlowfishCrypt->new(cost => 12, salt_random => 1, passphrase => $password);"),
            ("kotlin", "val hash = MessageDigest.getInstance(\"MD5\")", "val hash = BCrypt.hashpw(password, BCrypt.gensalt())"),
        ],
        "explanation": "Fast unsalted hashes are inadequate for password storage. Use adaptive password hashing such as Argon2id, scrypt, or bcrypt.",
    },
    {
        "slug": "xxe",
        "title": "XML External Entity",
        "category": "application-security",
        "languages": [
            ("java", "factory.newDocumentBuilder().parse(input)", "factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)"),
            ("python", "xml.etree.ElementTree.fromstring(data)", "defusedxml.ElementTree.fromstring(data)"),
            ("php", "$dom->loadXML($xml);", "$dom->loadXML($xml, LIBXML_NONET);"),
            ("csharp", "var doc = new XmlDocument(); doc.LoadXml(xml);", "var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };"),
            ("go", "xml.Unmarshal(data, &v)", "decoder := xml.NewDecoder(r); decoder.Strict = true"),
            ("ruby", "Nokogiri::XML(xml)", "Nokogiri::XML(xml) { |cfg| cfg.strict.nonet }"),
            ("scala", "XML.loadString(xml)", "Use a hardened XML parser with DTD disabled"),
            ("perl", "XML::LibXML->load_xml(string => $xml)", "XML::LibXML->new(no_network => 1)->load_xml(string => $xml)"),
            ("rust", "roxmltree::Document::parse(xml)", "Use parser settings that reject external entities"),
            ("javascript", "new DOMParser().parseFromString(xml, 'text/xml')", "Use XML parser configuration that disables external entities"),
        ],
        "explanation": "Unsafe XML parsers can fetch external entities and expose files or internal network resources. Disable DTDs and external entity resolution.",
    },
    {
        "slug": "insecure-deserialization",
        "title": "Insecure Deserialization",
        "category": "application-security",
        "languages": [
            ("python", "obj = pickle.loads(data)", "obj = json.loads(data)"),
            ("php", "$obj = unserialize($_POST['data']);", "$obj = json_decode($_POST['data'], true, flags: JSON_THROW_ON_ERROR);"),
            ("java", "new ObjectInputStream(in).readObject()", "Use JSON with strict schema validation"),
            ("ruby", "Marshal.load(data)", "JSON.parse(data)"),
            ("node", "nodeSerialize.unserialize(data)", "JSON.parse(data)"),
            ("csharp", "BinaryFormatter.Deserialize(stream)", "System.Text.Json.JsonSerializer.Deserialize<T>(json)"),
            ("go", "gob.NewDecoder(r).Decode(&v)", "json.NewDecoder(r).Decode(&v) with schema validation"),
            ("perl", "thaw($data)", "decode_json($data)"),
            ("rust", "bincode::deserialize(data)", "serde_json::from_slice(data) with validation"),
            ("kotlin", "ObjectInputStream(input).readObject()", "Json.decodeFromString<T>(json)"),
        ],
        "explanation": "Unsafe object deserialization can trigger gadget chains and code execution. Prefer simple data formats and validate structure strictly.",
    },
]


def make_documents():
    documents = []
    for vuln in VULNERABILITIES:
        for index, (language, insecure, secure) in enumerate(vuln["languages"], start=1):
            documents.append(
                {
                    "doc_key": f"{vuln['slug']}-{language}-{index}",
                    "title": f"{vuln['title']} Example {index} ({language})",
                    "category": vuln["category"],
                    "source_url": "",
                    "content": (
                        f"Language: {language}\n"
                        f"Vulnerability: {vuln['title']}\n"
                        f"Insecure code:\n{insecure}\n\n"
                        f"Secure code:\n{secure}\n\n"
                        f"Why insecure:\n{vuln['explanation']}"
                    ),
                }
            )
    return {"documents": documents}


def main():
    OUTPUT_PATH.write_text(json.dumps(make_documents(), indent=2), encoding="utf-8")
    print(f"Wrote 100 code-fix pairs to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
