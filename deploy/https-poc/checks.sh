# Exact expectations; any mismatch fails the run. TLS is always verified against the PoC CA.
fail=0
chk() { want=$1; got=$2; shift 2; if [ "$got" = "$want" ]; then echo "PASS $*"; else echo "FAIL $* (want $want got $got)"; fail=1; fi; }
L="--resolve learn.lab.test:8443:127.0.0.1 --resolve bank.lab.test:8443:127.0.0.1 --resolve splunk.lab.test:8443:127.0.0.1"
c() { curl -s -o /dev/null -w "%{http_code}" --cacert "$CA" $L "$@"; }
U="-u learner:$PW"
chk 200 "$(c $U https://learn.lab.test:8443/learn)" "learn page over TLS with credentials"
chk 401 "$(c https://learn.lab.test:8443/learn)" "no credentials is refused"
chk 401 "$(c -u learner:wrong https://learn.lab.test:8443/learn)" "wrong password is refused"
chk 200 "$(c $U https://bank.lab.test:8443/health)" "AcmeBank read-only view reachable"
chk 403 "$(c $U -X POST https://bank.lab.test:8443/health)" "AcmeBank POST denied"
chk 404 "$(c $U https://learn.lab.test:8443/api/allowlist)" "unlisted API path is 404"
chk 404 "$(c $U https://learn.lab.test:8443/api/compare-handoff)" "unlisted attack-adjacent path is 404"
chk 404 "$(c $U https://learn.lab.test:8443/api/academy/evidence/x)" "unlisted evidence path is 404"
chk 403 "$(c $U -X POST https://learn.lab.test:8443/learn)" "POST to the read-only tier denied"
chk 502 "$(c $U https://splunk.lab.test:8443/)" "Splunk hostname routes to :8000 (502: Splunk is not running in this PoC)"
code=$(c $U -X POST -H 'Content-Type: application/json' -d '{}' https://learn.lab.test:8443/api/launch)
case $code in 502|404|401|403) chk reached "$code" "attack-tier POST reaches the Attack Service";; *) echo "PASS attack-tier POST reaches the Attack Service (app answered $code)";; esac
chk 000 "$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" $L --tls-max 1.1 https://learn.lab.test:8443/learn)" "TLS 1.1 refused"
chk 308 "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/learn)" "HTTP redirects to HTTPS"
chk 000 "$(curl -s -o /dev/null -w '%{http_code}' $L https://learn.lab.test:8443/learn)" "unknown CA is rejected (no verification bypass)"
h=$(curl -s -D - -o /dev/null --cacert "$CA" $L $U https://learn.lab.test:8443/learn | tr -d '\r')
echo "$h" | grep -qi '^strict-transport-security' && echo "PASS HSTS header" || { echo "FAIL HSTS header"; fail=1; }
echo "$h" | grep -qi '^server: nginx/' && { echo "FAIL server version exposed"; fail=1; } || echo "PASS server version hidden"
n=0; for i in $(seq 1 25); do [ "$(c $U -X POST -H 'Content-Type: application/json' -d '{}' https://learn.lab.test:8443/api/launch)" = 503 ] && n=$((n+1)); done
[ $n -gt 0 ] && echo "PASS rate limit trips ($n of 25 refused with 503)" || { echo "FAIL rate limit"; fail=1; }
exit $fail
