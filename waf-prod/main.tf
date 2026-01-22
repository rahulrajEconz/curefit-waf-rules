provider "google" {
  project = var.project_id
  region  = "global"
}

resource "google_compute_security_policy" "prod-webacl" {
  name = var.policy_name
}

############################################
# 1. Cloudflare-Key HEADER
############################################
resource "google_compute_security_policy_rule" "cloudflare_key" {
  count           = var.enable_cloudflare_key ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.cloudflare_key_priority
  action          = var.cloudflare_key_action
  preview         = var.cloudflare_key_preview
  description     = var.cloudflare_key_description
  match {
    expr {
      expression = var.cloudflare_key_expression
    }
  }
}

###########################################
# 2. OfficeVpnPlusCoworkingSpaces
###########################################
resource "google_compute_security_policy_rule" "office_vpn_coworking" {
  for_each        = var.enable_office_vpn_coworking ? { for idx, val in chunklist(var.allowed_ip_ranges, 10) : idx => val } : {}
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.office_vpn_coworking_priority + tonumber(each.key)
  action          = var.office_vpn_coworking_action
  preview         = var.office_vpn_coworking_preview
  description     = var.office_vpn_coworking_description
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = each.value
    }
  }
}

###########################################
# 3. Deny non-office traffic to ai.curefit.co
###########################################
resource "google_compute_security_policy_rule" "deny_ai_host" {
  count           = var.enable_deny_ai_host ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.deny_ai_host_priority
  action          = var.deny_ai_host_action
  preview         = var.deny_ai_host_preview
  description     = var.deny_ai_host_description
  match {
    expr {
      expression = var.deny_ai_host_expression
    }
  }
}

###########################################
# 4. MissingCFConnectingIPRule
###########################################
resource "google_compute_security_policy_rule" "missing_cf_connecting_ip" {
  count           = var.enable_missing_cf_connecting_ip ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.missing_cf_connecting_ip_priority
  action          = var.missing_cf_connecting_ip_action
  preview         = var.missing_cf_connecting_ip_preview
  description     = var.missing_cf_connecting_ip_description
  match {
    expr {
      expression = var.missing_cf_connecting_ip_expression
    }
  }
}

###########################################
# 5. whitelist-cloudflare
###########################################
resource "google_compute_security_policy_rule" "whitelist_cloudflare" {
  count           = var.enable_whitelist_cloudflare ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.whitelist_cloudflare_priority
  action          = var.whitelist_cloudflare_action
  preview         = var.whitelist_cloudflare_preview
  description     = var.whitelist_cloudflare_description
  match {
    expr {
      expression = var.whitelist_cloudflare_expression
    }
  }
}

###########################################
# 6. whitelisted-ips
###########################################
resource "google_compute_security_policy_rule" "whitelisted_ip_address" {
  for_each        = var.enable_whitelisted_ip_address ? { for idx, val in chunklist(var.whitelisted_ip_address, 10) : idx => val } : {}
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.whitelisted_ip_address_priority + tonumber(each.key)
  action          = var.whitelisted_ip_address_action
  preview         = var.whitelisted_ip_address_preview
  description     = var.whitelisted_ip_address_description
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = each.value
    }
  }
}

###########################################
# 7A. Auth & Notifications – IP Rate Limiting
###########################################
resource "google_compute_security_policy_rule" "slow_rate_limit_auth" {
  count           = var.enable_slow_rate_limit_auth ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.slow_rate_limit_auth_priority
  action          = "rate_based_ban"
  preview         = var.slow_rate_limit_auth_preview
  description     = var.slow_rate_limit_auth_description
  match {
    expr {
      expression = var.slow_rate_limit_auth_expression
    }
  }
  rate_limit_options {
    conform_action = "allow"
    exceed_action  = "deny(429)"
    enforce_on_key = "IP"
    rate_limit_threshold {
      count        = var.slow_rate_limit_auth_count
      interval_sec = var.slow_rate_limit_auth_interval_sec
    }
    ban_threshold {
      count        = var.slow_rate_limit_auth_count
      interval_sec = var.slow_rate_limit_auth_interval_sec
    }
    ban_duration_sec = var.slow_rate_limit_auth_ban_duration
  }
}

###########################################
# 7B. FitnessPass – IP Rate Limiting
###########################################
resource "google_compute_security_policy_rule" "slow_rate_limit_fitness" {
  count           = var.enable_slow_rate_limit_fitness ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.slow_rate_limit_fitness_priority
  action          = "rate_based_ban"
  preview         = var.slow_rate_limit_fitness_preview
  description     = var.slow_rate_limit_fitness_description
  match {
    expr {
      expression = var.slow_rate_limit_fitness_expression
    }
  }
  rate_limit_options {
    conform_action = "allow"
    exceed_action  = "deny(429)"
    enforce_on_key = "IP"
    rate_limit_threshold {
      count        = var.slow_rate_limit_fitness_count
      interval_sec = var.slow_rate_limit_fitness_interval_sec
    }
    ban_threshold {
      count        = var.slow_rate_limit_fitness_count
      interval_sec = var.slow_rate_limit_fitness_interval_sec
    }
    ban_duration_sec = var.slow_rate_limit_fitness_ban_duration
  }
}

###########################################
# 7C. Cultwatch – IP Rate Limiting
###########################################
resource "google_compute_security_policy_rule" "slow_rate_limit_cultwatch" {
  count           = var.enable_slow_rate_limit_cultwatch ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.slow_rate_limit_cultwatch_priority
  action          = "rate_based_ban"
  preview         = var.slow_rate_limit_cultwatch_preview
  description     = var.slow_rate_limit_cultwatch_description
  match {
    expr {
      expression = var.slow_rate_limit_cultwatch_expression
    }
  }
  rate_limit_options {
    conform_action = "allow"
    exceed_action  = "deny(429)"
    enforce_on_key = "IP"
    rate_limit_threshold {
      count        = var.slow_rate_limit_cultwatch_count
      interval_sec = var.slow_rate_limit_cultwatch_interval_sec
    }
    ban_threshold {
      count        = var.slow_rate_limit_cultwatch_count
      interval_sec = var.slow_rate_limit_cultwatch_interval_sec
    }
    ban_duration_sec = var.slow_rate_limit_cultwatch_ban_duration
  }
}

###########################################
# 7D. Gymfit & Account – IP Rate Limiting
###########################################
resource "google_compute_security_policy_rule" "slow_rate_limit_account" {
  count           = var.enable_slow_rate_limit_account ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.slow_rate_limit_account_priority
  action          = "rate_based_ban"
  preview         = var.slow_rate_limit_account_preview
  description     = var.slow_rate_limit_account_description
  match {
    expr {
      expression = var.slow_rate_limit_account_expression
    }
  }
  rate_limit_options {
    conform_action = "allow"
    exceed_action  = "deny(429)"
    enforce_on_key = "IP"
    rate_limit_threshold {
      count        = var.slow_rate_limit_account_count
      interval_sec = var.slow_rate_limit_account_interval_sec
    }
    ban_threshold {
      count        = var.slow_rate_limit_account_count
      interval_sec = var.slow_rate_limit_account_interval_sec
    }
    ban_duration_sec = var.slow_rate_limit_account_ban_duration
  }
}

###########################################
# 8. blocklist-ips
###########################################
resource "google_compute_security_policy_rule" "blocklist_ip_address" {
  for_each        = var.enable_blocklist_ip_address ? { for idx, val in chunklist(var.blocked_ip_ranges, 10) : idx => val } : {}
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.blocklist_ip_address_priority + tonumber(each.key)
  action          = var.blocklist_ip_address_action
  preview         = var.blocklist_ip_address_preview
  description     = var.blocklist_ip_address_description
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = each.value
    }
  }
}

###########################################
# 9. Block Malicious Keyword – CEL
###########################################
resource "google_compute_security_policy_rule" "block_malicious_keywords" {
  count           = var.enable_block_malicious_keywords ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.block_malicious_keywords_priority
  action          = var.block_malicious_keywords_action
  preview         = var.block_malicious_keywords_preview
  description     = var.block_malicious_keywords_description
  match {
    expr {
      expression = var.block_malicious_keywords_expression
    }
  }
}

###########################################
# 10. DeviceID_Block_Blacklist – CEL
###########################################
resource "google_compute_security_policy_rule" "device_id_block" {
  count           = var.enable_device_id_block ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.device_id_block_priority
  action          = var.device_id_block_action
  preview         = var.device_id_block_preview
  description     = var.device_id_block_description
  match {
    expr {
      expression = var.device_id_block_expression
    }
  }
}

###########################################
# 11. Whitelist Device ID – CEL
###########################################
resource "google_compute_security_policy_rule" "whitelist_device_id" {
  count           = var.enable_whitelist_device_id ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.whitelist_device_id_priority
  action          = var.whitelist_device_id_action
  preview         = var.whitelist_device_id_preview
  description     = var.whitelist_device_id_description
  match {
    expr {
      expression = var.whitelist_device_id_expression
    }
  }
}

resource "google_compute_security_policy_rule" "geo_blacklist_cultsport" {
  count           = var.enable_geo_blacklist ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.geo_blacklist_cultsport_priority
  action          = var.geo_blacklist_cultsport_action
  preview         = var.geo_blacklist_cultsport_preview
  description     = var.geo_blacklist_cultsport_description
  match {
    expr {
      expression = "origin.region_code.matches('AO|AM|AZ|CN|PS|RU|UA|HK') && (request.headers['host'] == 'cultsport.com' || request.headers['host'].matches('.*sugarfit.*') || request.headers['host'].matches('.*Zencare.*'))"
    }
  }
}

###########################################
# 53. Method Enforcement – CEL
###########################################
resource "google_compute_security_policy_rule" "method_enforcement" {
  count           = var.enable_method_enforcement ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.method_enforcement_priority
  action          = var.method_enforcement_action
  preview         = var.method_enforcement_preview
  description     = var.method_enforcement_description
  match {
    expr {
      expression = var.method_enforcement_expression
    }
  }
}

###########################################
# 54. CVE Canary – CEL
###########################################
resource "google_compute_security_policy_rule" "cve_canary" {
  count           = var.enable_cve_canary ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.cve_canary_priority
  action          = var.cve_canary_action
  preview         = var.cve_canary_preview
  description     = var.cve_canary_description
  match {
    expr {
      expression = var.cve_canary_expression
    }
  }
}

###########################################
# 55. Login OTP Foreign – CEL
###########################################
resource "google_compute_security_policy_rule" "loginotp_foreign" {
  count           = var.enable_loginotp_foreign ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.loginotp_foreign_priority
  action          = var.loginotp_foreign_action
  preview         = var.loginotp_foreign_preview
  description     = var.loginotp_foreign_description
  match {
    expr {
      expression = var.loginotp_foreign_expression
    }
  }
}

###########################################
# 13. Exclude specific URI paths – CEL
###########################################
resource "google_compute_security_policy_rule" "uri_excluded" {
  count           = var.enable_uri_excluded ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.uri_excluded_priority
  action          = var.uri_excluded_action
  preview         = var.uri_excluded_preview
  description     = var.uri_excluded_description
  match {
    expr {
      expression = var.uri_excluded_expression
    }
  }
}

###########################################
# 14. Block requests with missing User-Agent – CEL
###########################################
resource "google_compute_security_policy_rule" "no_user_agent" {
  count           = var.enable_no_user_agent ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.no_user_agent_priority
  action          = var.no_user_agent_action
  preview         = var.no_user_agent_preview
  description     = var.no_user_agent_description
  match {
    expr {
      expression = var.no_user_agent_expression
    }
  }
}

###########################################
# 15. Block bad User-Agent bots – CEL
###########################################
resource "google_compute_security_policy_rule" "bad_user_agent_1" {
  count           = var.enable_bad_user_agent_1 ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.bad_user_agent_1_priority
  action          = var.bad_user_agent_1_action
  preview         = var.bad_user_agent_1_preview
  description     = var.bad_user_agent_1_description
  match {
    expr {
      expression = var.bad_user_agent_1_expression
    }
  }
}

resource "google_compute_security_policy_rule" "bad_user_agent_2" {
  count           = var.enable_bad_user_agent_2 ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.bad_user_agent_2_priority
  action          = var.bad_user_agent_2_action
  preview         = var.bad_user_agent_2_preview
  description     = var.bad_user_agent_2_description
  match {
    expr {
      expression = var.bad_user_agent_2_expression
    }
  }
}

###########################################
# 16. Block large query strings – CEL
###########################################
resource "google_compute_security_policy_rule" "query_size" {
  count           = var.enable_query_size ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.query_size_priority
  action          = var.query_size_action
  preview         = var.query_size_preview
  description     = var.query_size_description
  match {
    expr {
      expression = var.query_size_expression
    }
  }
}

###########################################
# 17. Block large Cookie headers – CEL
###########################################
resource "google_compute_security_policy_rule" "cookie_size" {
  count           = var.enable_cookie_size ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.cookie_size_priority
  action          = var.cookie_size_action
  preview         = var.cookie_size_preview
  description     = var.cookie_size_description
  match {
    expr {
      expression = var.cookie_size_expression
    }
  }
}

###########################################
# 19. Block long URI paths – CEL
###########################################
resource "google_compute_security_policy_rule" "uri_path_size" {
  count           = var.enable_uri_path_size ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.uri_path_size_priority
  action          = var.uri_path_size_action
  preview         = var.uri_path_size_preview
  description     = var.uri_path_size_description
  match {
    expr {
      expression = var.uri_path_size_expression
    }
  }
}

###########################################
# 20. Block EC2 Metadata SSRF – CEL
###########################################
resource "google_compute_security_policy_rule" "ec2_ssrf" {
  count           = var.enable_ec2_ssrf ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.ec2_ssrf_priority
  action          = var.ec2_ssrf_action
  preview         = var.ec2_ssrf_preview
  description     = var.ec2_ssrf_description
  match {
    expr {
      expression = var.ec2_ssrf_expression
    }
  }
}

###########################################
# 21. Consolidated LFI Protection – CEL
###########################################
resource "google_compute_security_policy_rule" "lfi_protection" {
  count           = var.enable_lfi_protection ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.lfi_protection_priority
  action          = var.lfi_protection_action
  preview         = var.lfi_protection_preview
  description     = var.lfi_protection_description
  match {
    expr {
      expression = var.lfi_protection_expression
    }
  }
}

resource "google_compute_security_policy_rule" "rfi_protection" {
  count           = var.enable_generic_rfi ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.rfi_protection_priority
  action          = var.rfi_protection_action
  preview         = var.rfi_protection_preview
  description     = var.rfi_protection_description
  match {
    expr {
      expression = var.rfi_protection_expression
    }
  }
}

resource "google_compute_security_policy_rule" "xss_protection" {
  count           = var.enable_xss ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.xss_protection_priority
  action          = var.xss_protection_action
  preview         = var.xss_protection_preview
  description     = var.xss_protection_description
  match {
    expr {
      expression = var.xss_protection_expression
    }
  }
}

resource "google_compute_security_policy_rule" "sqli_protection" {
  count           = var.enable_sqli ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.sqli_protection_priority
  action          = var.sqli_protection_action
  preview         = var.sqli_protection_preview
  description     = var.sqli_protection_description
  match {
    expr {
      expression = var.sqli_protection_expression
    }
  }
}

resource "google_compute_security_policy_rule" "java_rce_protection" {
  count           = var.enable_java_deserialization ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.java_rce_protection_priority
  action          = var.java_rce_protection_action
  preview         = var.java_rce_protection_preview
  description     = var.java_rce_protection_description
  match {
    expr {
      expression = var.java_rce_protection_expression
    }
  }
}

###########################################
# 42. Host header contains localhost – CEL
###########################################
resource "google_compute_security_policy_rule" "host_localhost" {
  count           = var.enable_host_localhost ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.host_localhost_priority
  action          = var.host_localhost_action
  preview         = var.host_localhost_preview
  description     = var.host_localhost_description
  match {
    expr {
      expression = var.host_localhost_expression
    }
  }
}

###########################################
# 43. PROPFIND Method – CEL
###########################################
resource "google_compute_security_policy_rule" "propfind_method" {
  count           = var.enable_propfind_method ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.propfind_method_priority
  action          = var.propfind_method_action
  preview         = var.propfind_method_preview
  description     = var.propfind_method_description
  match {
    expr {
      expression = var.propfind_method_expression
    }
  }
}

###########################################
# 44. Exploitable Paths – CEL
###########################################
resource "google_compute_security_policy_rule" "exploitable_paths" {
  count           = var.enable_exploitable_paths ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.exploitable_paths_priority
  action          = var.exploitable_paths_action
  preview         = var.exploitable_paths_preview
  description     = var.exploitable_paths_description
  match {
    expr {
      expression = var.exploitable_paths_expression
    }
  }
}

###########################################
# 45. Scanner Detection – CEL
###########################################
resource "google_compute_security_policy_rule" "scanner_detection" {
  count           = var.enable_scanner_detection ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.scanner_detection_priority
  action          = var.scanner_detection_action
  preview         = var.scanner_detection_preview
  description     = var.scanner_detection_description
  match {
    expr {
      expression = var.scanner_detection_expression
    }
  }
}


###########################################
# 47. Invoice-Ratelimit – CEL
###########################################
resource "google_compute_security_policy_rule" "invoice_ratelimit" {
  count           = var.enable_invoice_ratelimit ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.invoice_ratelimit_priority
  action          = var.invoice_ratelimit_action
  preview         = var.invoice_ratelimit_preview
  description     = var.invoice_ratelimit_description
  match {
    expr {
      expression = var.invoice_ratelimit_expression
    }
  }
}

###########################################
# 48. loginOtp – CEL
###########################################
resource "google_compute_security_policy_rule" "loginotp" {
  count           = var.enable_loginotp ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.loginotp_priority
  action          = var.loginotp_action
  preview         = var.loginotp_preview
  description     = var.loginotp_description
  match {
    expr {
      expression = var.loginotp_expression
    }
  }
}

###########################################
# 49. Sensitive_Paths – CEL
###########################################
resource "google_compute_security_policy_rule" "sensitive_paths" {
  count           = var.enable_sensitive_paths ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.sensitive_paths_priority
  action          = var.sensitive_paths_action
  preview         = var.sensitive_paths_preview
  description     = var.sensitive_paths_description
  match {
    expr {
      expression = var.sensitive_paths_expression
    }
  }
}

###########################################
# 50. Scanning Tool UA – CEL
###########################################
resource "google_compute_security_policy_rule" "scanning_tool_ua_1" {
  count           = var.enable_scanning_tool_ua ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.scanning_tool_ua_1_priority
  action          = var.scanning_tool_ua_1_action
  preview         = var.scanning_tool_ua_1_preview
  description     = var.scanning_tool_ua_1_description
  match {
    expr {
      expression = var.scanning_tool_ua_1_expression
    }
  }
}

resource "google_compute_security_policy_rule" "scanning_tool_ua_2" {
  count           = var.enable_scanning_tool_ua ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.scanning_tool_ua_2_priority
  action          = var.scanning_tool_ua_2_action
  preview         = var.scanning_tool_ua_2_preview
  description     = var.scanning_tool_ua_2_description
  match {
    expr {
      expression = var.scanning_tool_ua_2_expression
    }
  }
}

###########################################
# 51. Visibility_Endpoints – CEL
###########################################
resource "google_compute_security_policy_rule" "visibility_endpoints" {
  count           = var.enable_visibility_endpoints ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.visibility_endpoints_priority
  action          = var.visibility_endpoints_action
  preview         = var.visibility_endpoints_preview
  description     = var.visibility_endpoints_description
  match {
    expr {
      expression = var.visibility_endpoints_expression
    }
  }
}

###########################################
# 52. DDoS_rate_limit – CEL
###########################################
resource "google_compute_security_policy_rule" "ddos_rate_limit" {
  count           = var.enable_ddos_rate_limit ? 1 : 0
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = var.ddos_rate_limit_priority
  action          = var.ddos_rate_limit_action
  preview         = var.ddos_rate_limit_preview
  description     = var.ddos_rate_limit_description
  match {
    expr {
      expression = var.ddos_rate_limit_expression
    }
  }
}

############################################
# Default deny
############################################
resource "google_compute_security_policy_rule" "default_deny" {
  security_policy = google_compute_security_policy.prod-webacl.name
  priority        = 2147483647
  action          = "deny(403)"
  description     = "Default deny all"
  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = ["*"]
    }
  }
}
