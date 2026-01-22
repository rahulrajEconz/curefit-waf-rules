project_id  = "testing-bharani"
policy_name = "terraform-dataplatform-webacl-policy"

priority_number    = 10
rule_action        = "allow"
ip_address_preview = true
rule_description   = "Allow traffic from approved IP ranges"
allowed_ip_ranges = [
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
  "172.16.0.0/12"
]

scanner_detection_priority    = 30
scanner_detection_action      = "deny(403)"
scanner_detection_preview     = true
scanner_detection_description = "Cloud Armor XSS/SQLi - COUNT"
scanner_detection_expression  = "evaluatePreconfiguredWaf('scannerdetection-v33-stable', {'sensitivity': 1})"

java_deserialization_priority    = 40
java_deserialization_action      = "deny(403)"
java_deserialization_preview     = true
java_deserialization_description = "JavaDeserialization - COUNT"
java_deserialization_expression  = "evaluatePreconfiguredWaf('java-v33-stable')"

localhost_header_priority    = 50
localhost_HEADER_action      = "allow"
localhost_header_preview     = true
localhost_header_description = "Block localhost Host header - COUNT"
localhost_header_expression  = "evaluatePreconfiguredWaf('protocolattack-v33-stable')"

profind_method_priority    = 60
profind_method_action      = "allow"
profind_method_preview     = true
profind_method_description = "Block PROPFIND HTTP method - COUNT"
profind_method_expression  = "evaluatePreconfiguredWaf('methodenforcement-v33-stable')"

lfi_protection_priority    = 70
lfi_protection_action      = "allow"
lfi_protection_preview     = true
lfi_protection_description = "Global LFI Protection (Merged)"
lfi_protection_expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"

reactjs_rce_body_priority    = 90
reactjs_rce_body_action      = "allow"
reactjs_rce_body_preview     = true
reactjs_rce_body_description = "Block ReactJS RCE payloads in request body - COUNT"
reactjs_rce_body_expression  = "evaluatePreconfiguredWaf('rce-v33-stable')"

no_user_agent_header_priority    = 100
no_user_agent_header_action      = "deny(403)"
no_user_agent_header_preview     = true
no_user_agent_header_description = "Block requests with missing User-Agent header - COUNT"
no_user_agent_header_expression  = "request.headers['user-agent'] == ''"

sizerestrictions_querystring_priority    = 120
sizerestrictions_querystring_action      = "deny(403)"
sizerestrictions_querystring_preview     = true
sizerestrictions_querystring_description = "Block requests with oversized query strings - COUNT"
sizerestrictions_querystring_expression  = "size(request.query) > 4096"

sizerestrictions_cookie_header_priority    = 130
sizerestrictions_cookie_header_action      = "allow"
sizerestrictions_cookie_header_preview     = true
sizerestrictions_cookie_header_description = "Block requests with oversized Cookie headers"
sizerestrictions_cookie_header_expression  = "size(request.headers['cookie']) > 4096"

sizerestrictions_uripath_priority    = 150
sizerestrictions_uripath_action      = "allow"
sizerestrictions_uripath_preview     = true
sizerestrictions_uripath_description = "Block requests with overly long URI paths"
sizerestrictions_uripath_expression  = "size(request.path) > 2048"

ec2_metadata_ssrf_priority    = 160
ec2_metadata_ssrf_action      = "allow"
ec2_metadata_ssrf_preview     = true
ec2_metadata_ssrf_description = "Block SSRF attempts targeting EC2 metadata"
ec2_metadata_ssrf_expression  = "evaluatePreconfiguredWaf('protocolattack-v33-stable')"


generic_rfi_priority    = 190
generic_rfi_action      = "allow"
generic_rfi_preview     = true
generic_rfi_description = "Block Remote File Inclusion attempts"
generic_rfi_expression  = "evaluatePreconfiguredWaf('rfi-v33-stable')"

cross_site_scripting_priority    = 200
cross_site_scripting_action      = "allow"
cross_site_scripting_preview     = true
cross_site_scripting_description = "Block Cross-Site Scripting (XSS) attacks"
cross_site_scripting_expression  = "evaluatePreconfiguredWaf('xss-v33-stable')"
