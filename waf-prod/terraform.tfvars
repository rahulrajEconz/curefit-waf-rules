project_id  = "testing-bharani"
policy_name = "terraform-prod-webacl-policy"

cloudflare_key_priority    = 10
cloudflare_key_action      = "allow"
cloudflare_key_preview     = true
cloudflare_key_description = "Allow requests with valid Cloudflare key header"
cloudflare_key_expression  = "has(request.headers['cloudflare-key']) && request.headers['cloudflare-key'] != ''"

office_vpn_coworking_priority    = 20
office_vpn_coworking_action      = "allow"
office_vpn_coworking_preview     = true
office_vpn_coworking_description = "Allow Office VPN and Coworking Spaces traffic"
allowed_ip_ranges = [
  "182.76.142.214/32",
  "103.171.98.45/32",
  "180.151.72.58/32",
  "106.51.80.216/32",
  "43.224.128.72/32",
  "180.151.198.14/32",
  "106.51.73.13/32",
  "103.88.158.194/32",
  "152.58.244.209/32",
  "157.66.185.66/32",
  "180.151.37.122/32",
  "182.73.173.198/32",
  "43.224.159.169/32",
  "106.221.207.122/32",
  "106.51.91.38/32",
  "103.84.129.158/32",
  "125.20.157.162/32"
]

deny_ai_host_priority    = 30
deny_ai_host_action      = "deny(403)"
deny_ai_host_preview     = true
deny_ai_host_description = "Deny non-office traffic to ai.curefit.co"
deny_ai_host_expression  = "has(request.headers['host']) && request.headers['host'] == 'ai.curefit.co'"

missing_cf_connecting_ip_priority    = 40
missing_cf_connecting_ip_action      = "allow"
missing_cf_connecting_ip_preview     = true
missing_cf_connecting_ip_description = "Deny requests missing CF-Connecting-IP header"
missing_cf_connecting_ip_expression  = "has(request.headers['cf-connecting-ip']) == false"

whitelist_cloudflare_priority    = 50
whitelist_cloudflare_action      = "allow"
whitelist_cloudflare_preview     = true
whitelist_cloudflare_description = "Allow traffic that passed through Cloudflare"
whitelist_cloudflare_expression  = "has(request.headers['x-through-cloudflare']) && request.headers['x-through-cloudflare'] == 'yes'"

whitelisted_ip_address_priority    = 60
whitelisted_ip_address_action      = "allow"
whitelisted_ip_address_preview     = true
whitelisted_ip_address_description = "Allow traffic from whitelisted IP ranges"
whitelisted_ip_address = [
  "182.76.142.214/32",
  "43.224.159.201/32",
  "49.249.133.250/32",
  "35.154.32.160/32",
  "103.88.157.178/32",
  "3.111.118.210/32",
  "103.88.157.194/32",
  "3.6.76.17/32",
  "103.88.158.194/32",
  "192.168.0.0/16",
  "13.232.121.54/32",
  "10.0.0.0/8",
  "182.73.173.198/32",
  "43.224.159.209/32",
  "117.24.121.252/32",
  "169.254.0.0/16",
  "13.126.77.43/32",
  "3.109.80.250/32",
  "43.224.159.169/32",
  "182.156.75.86/32",
  "106.51.91.38/32",
  "103.84.129.158/32",
  "172.16.0.0/12",
  "35.154.93.182/32",
  "13.234.54.8/32",
  "13.126.169.175/32"
]

slow_rate_limit_auth_priority     = 70
slow_rate_limit_auth_preview      = true
slow_rate_limit_auth_description  = "Slow rate limit for auth & notifications"
slow_rate_limit_auth_expression   = "request.path.matches('^/api/auth/loginPhoneSendOtp') || request.path.matches('^/api/user/status') || request.path.matches('^/api/notifications/.*') || request.path.matches('^/sendInvoice') || request.path.matches('^/api/user/verifyEmailThroughOtp')"
slow_rate_limit_auth_count        = 10
slow_rate_limit_auth_interval_sec = 60
slow_rate_limit_auth_ban_duration = 300

slow_rate_limit_fitness_priority     = 80
slow_rate_limit_fitness_preview      = false
slow_rate_limit_fitness_description  = "Slow rate limit for FitnessPass APIs"
slow_rate_limit_fitness_expression   = "request.path.matches('^/api/fitnessPass/eligibility') || request.path.matches('^/api/fitnessPass/activate') || request.path.matches('^/api/auth/loginphoneverifyotp') || request.path.matches('^/user/setName') || request.path.matches('^/api/user/setEmailSendOtp')"
slow_rate_limit_fitness_count        = 10
slow_rate_limit_fitness_interval_sec = 60
slow_rate_limit_fitness_ban_duration = 300

slow_rate_limit_cultwatch_priority     = 90
slow_rate_limit_cultwatch_preview      = true
slow_rate_limit_cultwatch_description  = "Slow rate limit for Cultwatch APIs"
slow_rate_limit_cultwatch_expression   = "request.path.matches('^/api/v2/cultwatch/serviceRequest/.*') || request.path.matches('^/api/v2/cultwatch/order/.*') || request.path.matches('^/api/v2/cultwatch/invoice/.*') || request.path.matches('^/api/v2/cultwatch/review/.*') || request.path.matches('^/api/auth/email/.*')"
slow_rate_limit_cultwatch_count        = 20
slow_rate_limit_cultwatch_interval_sec = 60
slow_rate_limit_cultwatch_ban_duration = 300

slow_rate_limit_account_priority     = 100
slow_rate_limit_account_preview      = true
slow_rate_limit_account_description  = "Slow rate limit for gymfit & account APIs"
slow_rate_limit_account_expression   = "request.path.matches('^/api/gymfit/.*') || request.path.matches('^/api/pack/cult/.*') || request.path.matches('^/api/user/deleteAccountVerifyOtp') || request.path.matches('^/api/user/deleteAccountSendOtp') || request.path.matches('^/api/auth/email/otprequest')"
slow_rate_limit_account_count        = 5
slow_rate_limit_account_interval_sec = 60
slow_rate_limit_account_ban_duration = 600

blocklist_ip_address_priority    = 110
blocklist_ip_address_action      = "allow"
blocklist_ip_address_preview     = true
blocklist_ip_address_description = "Allow traffic from whitelisted IP ranges"
blocked_ip_ranges = [
  "143.244.183.141/32", "162.243.175.244/32", "143.198.100.32/32", "5.157.131.225/32", "49.43.181.214/32",
  "13.233.143.94/32", "103.82.210.87/32", "35.80.0.0/12", "150.129.131.115/32", "13.126.139.23/32",
  "35.87.168.241/32", "206.189.137.196/32", "160.202.36.188/32", "45.131.212.206/32", "49.36.236.213/32",
  "147.182.192.33/32", "164.100.203.94/32", "157.230.225.197/32", "18.236.181.123/32", "45.92.247.145/32",
  "45.154.228.121/32", "3.17.216.10/32", "3.108.222.231/32", "161.35.230.107/32", "20.89.101.244/32",
  "3.236.133.143/32", "54.201.119.207/32", "139.180.136.80/32", "143.198.123.152/32", "44.233.116.19/32",
  "64.227.21.121/32", "109.207.130.0/32", "193.151.161.105/32", "193.8.231.21/32",
  "2402:e280:3e22:0593:d1c1:2dfc:a4af:827d/128", "2409:4072:080e:9b69:c67c:5e7b:b9bf:e46c/128",
  "2a01:07a7:0002:25fd:0225:90ff:fe8f:52c4/128", "2a02:4780:0000:0000:0000:0000:0000:0040/128"
]

block_malicious_keywords_priority    = 120
block_malicious_keywords_action      = "deny(403)"
block_malicious_keywords_preview     = true
block_malicious_keywords_description = "Block OAST / Burp collaborator domains"
block_malicious_keywords_expression  = "request.query.matches(\"(?i)\\\\b(?:oastify\\\\.com|burpcollaborator\\\\.net|beeceptor\\\\.com|oast\\\\.(?:online|site|me|live|pro|fun))\\\\b\")"

device_id_block_priority    = 130
device_id_block_action      = "deny(403)"
device_id_block_preview     = true
device_id_block_description = "Blacklist static Device IDs in Cookies"
device_id_block_expression  = "has(request.headers['cookie']) && request.headers['cookie'].matches('s:866d15b9-d4bc-4213-84c9-1553258fc79c|s:d87bce3e-e972-4d22-9756-61838eece64e')"

whitelist_device_id_priority    = 140
whitelist_device_id_action      = "allow"
whitelist_device_id_preview     = true
whitelist_device_id_description = "Whitelist Device IDs"
whitelist_device_id_expression  = "has(request.headers['deviceid']) && request.headers['deviceid'].matches('85220BEA-5EFC-4E94-814A-B3E6FD154EB8|ED789368-3B4C-4FF3-8A0D-EBF0FFAB8F08')"

geo_blacklist_cultsport_priority    = 150
geo_blacklist_cultsport_action      = "allow"
geo_blacklist_cultsport_preview     = true
geo_blacklist_cultsport_description = "Blacklist Geo for cultsport.com (Merged)"

uri_excluded_priority    = 230
uri_excluded_action      = "allow"
uri_excluded_preview     = true
uri_excluded_description = "URI path excluded in AWS Managed rules"
uri_excluded_expression  = "request.path == '/production/trino-event-listener' || request.path == '/echidna/automation/deployOnPullRequest'"

no_user_agent_priority    = 240
no_user_agent_action      = "deny(403)"
no_user_agent_preview     = true
no_user_agent_description = "Block requests with missing or empty User-Agent header"
no_user_agent_expression  = "!has(request.headers['user-agent']) || request.headers['user-agent'] == ''"

bad_user_agent_1_priority    = 250
bad_user_agent_1_action      = "deny(403)"
bad_user_agent_1_preview     = true
bad_user_agent_1_description = "Block requests from bad User-Agent bots (curl, wget)"
bad_user_agent_1_expression  = "has(request.headers['user-agent']) && (request.headers['user-agent'].lower().contains('curl') || request.headers['user-agent'].lower().contains('python-requests') || request.headers['user-agent'].lower().contains('wget'))"

bad_user_agent_2_priority    = 260
bad_user_agent_2_action      = "deny(403)"
bad_user_agent_2_preview     = true
bad_user_agent_2_description = "Block requests from bad User-Agent bots (postman, scrapy)"
bad_user_agent_2_expression  = "has(request.headers['user-agent']) && (request.headers['user-agent'].lower().contains('postmanruntime') || request.headers['user-agent'].lower().contains('scrapy') || request.headers['user-agent'].lower().contains('httpclient'))"

query_size_priority    = 270
query_size_action      = "deny(403)"
query_size_preview     = true
query_size_description = "Block requests with query string larger than 4096 bytes"
query_size_expression  = "size(request.query) > 4096"

cookie_size_priority    = 280
cookie_size_action      = "deny(403)"
cookie_size_preview     = true
cookie_size_description = "Block requests with cookie header larger than 4096 bytes"
cookie_size_expression  = "size(request.headers['cookie']) > 4096"

uri_path_size_priority    = 300
uri_path_size_action      = "deny(403)"
uri_path_size_preview     = true
uri_path_size_description = "Block requests with URI path longer than 2048 characters"
uri_path_size_expression  = "size(request.path) > 2048"

ec2_ssrf_priority    = 310
ec2_ssrf_action      = "deny(403)"
ec2_ssrf_preview     = true
ec2_ssrf_description = "Block requests triggering EC2 Metadata SSRF"
ec2_ssrf_expression  = "evaluatePreconfiguredWaf('protocolattack-v33-stable')"

generic_lfi_priority    = 320
generic_lfi_action      = "deny(403)"
generic_lfi_preview     = true
generic_lfi_description = "Block Generic LFI attacks in query arguments"
generic_lfi_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

generic_lfi_uripath_priority    = 330
generic_lfi_uripath_action      = "deny(403)"
generic_lfi_uripath_preview     = true
generic_lfi_uripath_description = "Block Generic LFI attacks in URI path"
generic_lfi_uripath_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

generic_lfi_body_priority    = 340
generic_lfi_body_action      = "deny(403)"
generic_lfi_body_preview     = true
generic_lfi_body_description = "Block Generic LFI attacks in request body"
generic_lfi_body_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

restricted_ext_uripath_priority    = 350
restricted_ext_uripath_action      = "deny(403)"
restricted_ext_uripath_preview     = true
restricted_ext_uripath_description = "Block restricted file extensions in URI path"
restricted_ext_uripath_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

restricted_ext_query_priority    = 360
restricted_ext_query_action      = "deny(403)"
restricted_ext_query_preview     = true
restricted_ext_query_description = "Block restricted file extensions in query arguments"
restricted_ext_query_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

rfi_protection_priority    = 370
rfi_protection_action      = "deny(403)"
rfi_protection_preview     = true
rfi_protection_description = "Global RFI Protection (Merged)"
rfi_protection_expression  = "evaluatePreconfiguredWaf('rfi-v33-stable')"

xss_protection_priority    = 400
xss_protection_action      = "deny(403)"
xss_protection_preview     = true
xss_protection_description = "Global XSS Protection (Merged)"
xss_protection_expression  = "evaluatePreconfiguredWaf('xss-v33-stable')"

sqli_protection_priority    = 440
sqli_protection_action      = "deny(403)"
sqli_protection_preview     = true
sqli_protection_description = "Global SQLi Protection (Merged)"
sqli_protection_expression  = "evaluatePreconfiguredWaf('sqli-v33-stable')"

java_rce_protection_priority    = 490
java_rce_protection_action      = "deny(403)"
java_rce_protection_preview     = true
java_rce_protection_description = "Global Java RCE Protection (Merged)"
java_rce_protection_expression  = "evaluatePreconfiguredWaf('java-v33-stable')"

host_localhost_priority    = 530
host_localhost_action      = "deny(403)"
host_localhost_preview     = true
host_localhost_description = "Block Host header containing localhost"
host_localhost_expression  = "has(request.headers['host']) && request.headers['host'].contains('localhost')"

propfind_method_priority    = 540
propfind_method_action      = "deny(403)"
propfind_method_preview     = true
propfind_method_description = "Block PROPFIND HTTP method"
propfind_method_expression  = "request.method == 'PROPFIND'"

exploitable_paths_priority    = 550
exploitable_paths_action      = "deny(403)"
exploitable_paths_preview     = true
exploitable_paths_description = "Block exploitable paths"
exploitable_paths_expression  = "request.path.matches('/wp-admin/|/phpmyadmin/')"

scanner_detection_priority    = 560
scanner_detection_action      = "deny(403)"
scanner_detection_preview     = true
scanner_detection_description = "Block scanner activity"
scanner_detection_expression  = "evaluatePreconfiguredWaf('scannerdetection-v33-stable')"

lfi_priority    = 570
lfi_action      = "deny(403)"
lfi_preview     = true
lfi_description = "Block LFI Root"
lfi_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

invoice_ratelimit_priority    = 580
invoice_ratelimit_action      = "deny(403)"
invoice_ratelimit_preview     = true
invoice_ratelimit_description = "Invoice Ratelimit"
invoice_ratelimit_expression  = "request.path.matches('/api/invoice/')"

loginotp_priority    = 590
loginotp_action      = "deny(403)"
loginotp_preview     = true
loginotp_description = "Login OTP"
loginotp_expression  = "request.path.matches('/api/login/otp')"

sensitive_paths_priority    = 600
sensitive_paths_action      = "deny(403)"
sensitive_paths_preview     = true
sensitive_paths_description = "Sensitive Paths"
sensitive_paths_expression  = "request.path.matches('/etc/passwd')"

scanning_tool_ua_1_priority    = 610
scanning_tool_ua_1_action      = "deny(403)"
scanning_tool_ua_1_preview     = true
scanning_tool_ua_1_description = "Scanning Tool UA 1"
scanning_tool_ua_1_expression  = "has(request.headers['user-agent']) && request.headers['user-agent'].contains('nuclei')"

scanning_tool_ua_2_priority    = 620
scanning_tool_ua_2_action      = "deny(403)"
scanning_tool_ua_2_preview     = true
scanning_tool_ua_2_description = "Scanning Tool UA 2"
scanning_tool_ua_2_expression  = "has(request.headers['user-agent']) && request.headers['user-agent'].contains('nikto')"

visibility_endpoints_priority    = 630
visibility_endpoints_action      = "deny(403)"
visibility_endpoints_preview     = true
visibility_endpoints_description = "Visibility Endpoints"
visibility_endpoints_expression  = "request.path.matches('/api/visibility/')"

ddos_rate_limit_priority    = 640
ddos_rate_limit_action      = "deny(403)"
ddos_rate_limit_preview     = true
ddos_rate_limit_description = "DDoS Rate Limit"
ddos_rate_limit_expression  = "has(request.headers['x-forwarded-for'])"
