variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "testing-bharani"
}

variable "policy_name" {
  description = "The name of the security policy"
  type        = string
}

###########################################
# Toggles (from toggles.tf)
###########################################

variable "enable_cloudflare_key" {
  description = "Enable Cloudflare Key rule"
  type        = bool
  default     = true
}

variable "enable_office_vpn_coworking" {
  description = "Enable Office VPN and Coworking Spaces rule"
  type        = bool
  default     = true
}

variable "enable_deny_ai_host" {
  description = "Enable Deny ai.curefit.co rule"
  type        = bool
  default     = true
}

variable "enable_missing_cf_connecting_ip" {
  description = "Enable Missing CF Connecting IP rule"
  type        = bool
  default     = true
}

variable "enable_whitelist_cloudflare" {
  description = "Enable Whitelist Cloudflare rule"
  type        = bool
  default     = true
}

variable "enable_whitelisted_ip_address" {
  description = "Enable Whitelisted IP Address rule"
  type        = bool
  default     = true
}

variable "enable_slow_rate_limit_auth" {
  description = "Enable Slow Rate Limit Auth rule"
  type        = bool
  default     = true
}

variable "enable_slow_rate_limit_fitness" {
  description = "Enable Slow Rate Limit Fitness rule"
  type        = bool
  default     = true
}

variable "enable_slow_rate_limit_cultwatch" {
  description = "Enable Slow Rate Limit Cultwatch rule"
  type        = bool
  default     = true
}

variable "enable_slow_rate_limit_account" {
  description = "Enable Slow Rate Limit Account rule"
  type        = bool
  default     = true
}

variable "enable_blocklist_ip_address" {
  description = "Enable Blocklist IP Address rule"
  type        = bool
  default     = true
}

variable "enable_block_malicious_keywords" {
  description = "Enable Block Malicious Keywords rule"
  type        = bool
  default     = true
}

variable "enable_device_id_block" {
  description = "Enable Device ID Block rule"
  type        = bool
  default     = true
}

variable "enable_whitelist_device_id" {
  description = "Enable Whitelist Device ID rule"
  type        = bool
  default     = true
}

variable "enable_geo_blacklist" {
  description = "Enable Geo Blacklist rules"
  type        = bool
  default     = true
}

variable "enable_uri_excluded" {
  description = "Enable URI Excluded rule"
  type        = bool
  default     = true
}

variable "enable_no_user_agent" {
  description = "Enable No User Agent rule"
  type        = bool
  default     = true
}

variable "enable_bad_user_agent_1" {
  description = "Enable Bad User Agent 1 rule"
  type        = bool
  default     = true
}

variable "enable_bad_user_agent_2" {
  description = "Enable Bad User Agent 2 rule"
  type        = bool
  default     = true
}

variable "enable_query_size" {
  description = "Enable Query Size rule"
  type        = bool
  default     = true
}

variable "enable_cookie_size" {
  description = "Enable Cookie Size rule"
  type        = bool
  default     = true
}

variable "enable_uri_path_size" {
  description = "Enable URI Path Size rule"
  type        = bool
  default     = true
}

variable "enable_ec2_ssrf" {
  description = "Enable EC2 SSRF rule"
  type        = bool
  default     = true
}

variable "enable_lfi_protection" {
  description = "Enable Consolidated LFI Protection rules"
  type        = bool
  default     = true
}

variable "enable_generic_rfi" {
  description = "Enable Generic RFI rules"
  type        = bool
  default     = true
}

variable "enable_xss" {
  description = "Enable XSS rules"
  type        = bool
  default     = true
}

variable "enable_sqli" {
  description = "Enable SQLi rules"
  type        = bool
  default     = true
}

variable "enable_java_deserialization" {
  description = "Enable Java Deserialization rules"
  type        = bool
  default     = true
}

variable "enable_host_localhost" {
  description = "Enable Host Localhost rule"
  type        = bool
  default     = true
}

variable "enable_propfind_method" {
  description = "Enable PROPFIND Method rule"
  type        = bool
  default     = true
}

variable "enable_exploitable_paths" {
  description = "Enable Exploitable Paths rule"
  type        = bool
  default     = true
}

variable "enable_scanner_detection" {
  description = "Enable Scanner Detection rule"
  type        = bool
  default     = true
}


variable "enable_invoice_ratelimit" {
  description = "Enable Invoice Ratelimit rule"
  type        = bool
  default     = true
}

variable "enable_loginotp" {
  description = "Enable Login OTP rule"
  type        = bool
  default     = true
}

variable "enable_sensitive_paths" {
  description = "Enable Sensitive Paths rule"
  type        = bool
  default     = true
}

variable "enable_scanning_tool_ua" {
  description = "Enable Scanning Tool UA rules"
  type        = bool
  default     = true
}

variable "enable_visibility_endpoints" {
  description = "Enable Visibility Endpoints rule"
  type        = bool
  default     = true
}

variable "enable_ddos_rate_limit" {
  description = "Enable DDoS Rate Limit rule"
  type        = bool
  default     = true
}


###########################################
# Rule Parameters
###########################################

variable "cloudflare_key_priority" { type = number }
variable "cloudflare_key_action" { type = string }
variable "cloudflare_key_preview" {
  type    = bool
  default = true
}
variable "cloudflare_key_description" { type = string }
variable "cloudflare_key_expression" { type = string }

variable "office_vpn_coworking_priority" { type = number }
variable "office_vpn_coworking_action" { type = string }
variable "office_vpn_coworking_preview" {
  type    = bool
  default = true
}
variable "office_vpn_coworking_description" { type = string }
variable "allowed_ip_ranges" { type = list(string) }

variable "deny_ai_host_priority" { type = number }
variable "deny_ai_host_action" { type = string }
variable "deny_ai_host_preview" {
  type    = bool
  default = true
}
variable "deny_ai_host_description" { type = string }
variable "deny_ai_host_expression" { type = string }

variable "missing_cf_connecting_ip_priority" { type = number }
variable "missing_cf_connecting_ip_action" { type = string }
variable "missing_cf_connecting_ip_preview" {
  type    = bool
  default = true
}
variable "missing_cf_connecting_ip_description" { type = string }
variable "missing_cf_connecting_ip_expression" { type = string }

variable "whitelist_cloudflare_priority" { type = number }
variable "whitelist_cloudflare_action" { type = string }
variable "whitelist_cloudflare_preview" {
  type    = bool
  default = true
}
variable "whitelist_cloudflare_description" { type = string }
variable "whitelist_cloudflare_expression" { type = string }

variable "whitelisted_ip_address_priority" { type = number }
variable "whitelisted_ip_address_action" { type = string }
variable "whitelisted_ip_address_preview" {
  type    = bool
  default = true
}
variable "whitelisted_ip_address_description" { type = string }
variable "whitelisted_ip_address" { type = list(string) }

variable "slow_rate_limit_auth_priority" { type = number }
variable "slow_rate_limit_auth_preview" {
  type    = bool
  default = true
}
variable "slow_rate_limit_auth_description" { type = string }
variable "slow_rate_limit_auth_expression" { type = string }
variable "slow_rate_limit_auth_count" { type = number }
variable "slow_rate_limit_auth_interval_sec" { type = number }
variable "slow_rate_limit_auth_ban_duration" { type = number }

variable "slow_rate_limit_fitness_priority" { type = number }
variable "slow_rate_limit_fitness_preview" {
  type    = bool
  default = true
}
variable "slow_rate_limit_fitness_description" { type = string }
variable "slow_rate_limit_fitness_expression" { type = string }
variable "slow_rate_limit_fitness_count" { type = number }
variable "slow_rate_limit_fitness_interval_sec" { type = number }
variable "slow_rate_limit_fitness_ban_duration" { type = number }

variable "slow_rate_limit_cultwatch_priority" { type = number }
variable "slow_rate_limit_cultwatch_preview" {
  type    = bool
  default = true
}
variable "slow_rate_limit_cultwatch_description" { type = string }
variable "slow_rate_limit_cultwatch_expression" { type = string }
variable "slow_rate_limit_cultwatch_count" { type = number }
variable "slow_rate_limit_cultwatch_interval_sec" { type = number }
variable "slow_rate_limit_cultwatch_ban_duration" { type = number }

variable "slow_rate_limit_account_priority" { type = number }
variable "slow_rate_limit_account_preview" {
  type    = bool
  default = true
}
variable "slow_rate_limit_account_description" { type = string }
variable "slow_rate_limit_account_expression" { type = string }
variable "slow_rate_limit_account_count" { type = number }
variable "slow_rate_limit_account_interval_sec" { type = number }
variable "slow_rate_limit_account_ban_duration" { type = number }

variable "blocked_ip_ranges" { type = list(string) }
variable "blocklist_ip_address_priority" { type = number }
variable "blocklist_ip_address_action" { type = string }
variable "blocklist_ip_address_preview" {
  type    = bool
  default = true
}
variable "blocklist_ip_address_description" { type = string }

variable "block_malicious_keywords_priority" { type = number }
variable "block_malicious_keywords_action" { type = string }
variable "block_malicious_keywords_preview" {
  type    = bool
  default = true
}
variable "block_malicious_keywords_description" { type = string }
variable "block_malicious_keywords_expression" { type = string }

variable "device_id_block_priority" { type = number }
variable "device_id_block_action" { type = string }
variable "device_id_block_preview" {
  type    = bool
  default = true
}
variable "device_id_block_description" { type = string }
variable "device_id_block_expression" { type = string }

variable "whitelist_device_id_priority" { type = number }
variable "whitelist_device_id_action" { type = string }
variable "whitelist_device_id_preview" {
  type    = bool
  default = true
}
variable "whitelist_device_id_description" { type = string }
variable "whitelist_device_id_expression" { type = string }

variable "geo_blacklist_cultsport_priority" { type = number }
variable "geo_blacklist_cultsport_action" { type = string }
variable "geo_blacklist_cultsport_preview" {
  type    = bool
  default = true
}
variable "geo_blacklist_cultsport_description" { type = string }

variable "uri_excluded_priority" { type = number }
variable "uri_excluded_action" { type = string }
variable "uri_excluded_preview" {
  type    = bool
  default = true
}
variable "uri_excluded_description" { type = string }
variable "uri_excluded_expression" { type = string }

variable "no_user_agent_priority" { type = number }
variable "no_user_agent_action" { type = string }
variable "no_user_agent_preview" {
  type    = bool
  default = true
}
variable "no_user_agent_description" { type = string }
variable "no_user_agent_expression" { type = string }

variable "bad_user_agent_1_priority" { type = number }
variable "bad_user_agent_1_action" { type = string }
variable "bad_user_agent_1_preview" {
  type    = bool
  default = true
}
variable "bad_user_agent_1_description" { type = string }
variable "bad_user_agent_1_expression" { type = string }

variable "bad_user_agent_2_priority" { type = number }
variable "bad_user_agent_2_action" { type = string }
variable "bad_user_agent_2_preview" {
  type    = bool
  default = true
}
variable "bad_user_agent_2_description" { type = string }
variable "bad_user_agent_2_expression" { type = string }

variable "query_size_priority" { type = number }
variable "query_size_action" { type = string }
variable "query_size_preview" {
  type    = bool
  default = true
}
variable "query_size_description" { type = string }
variable "query_size_expression" { type = string }

variable "cookie_size_priority" { type = number }
variable "cookie_size_action" { type = string }
variable "cookie_size_preview" {
  type    = bool
  default = true
}
variable "cookie_size_description" { type = string }
variable "cookie_size_expression" { type = string }

variable "uri_path_size_priority" { type = number }
variable "uri_path_size_action" { type = string }
variable "uri_path_size_preview" {
  type    = bool
  default = true
}
variable "uri_path_size_description" { type = string }
variable "uri_path_size_expression" { type = string }

variable "ec2_ssrf_priority" { type = number }
variable "ec2_ssrf_action" { type = string }
variable "ec2_ssrf_preview" {
  type    = bool
  default = true
}
variable "ec2_ssrf_description" { type = string }
variable "ec2_ssrf_expression" { type = string }

variable "lfi_protection_priority" { type = number }
variable "lfi_protection_action" { type = string }
variable "lfi_protection_preview" {
  type    = bool
  default = true
}
variable "lfi_protection_description" { type = string }
variable "lfi_protection_expression" { type = string }

variable "rfi_protection_priority" { type = number }
variable "rfi_protection_action" { type = string }
variable "rfi_protection_preview" {
  type    = bool
  default = true
}
variable "rfi_protection_description" { type = string }
variable "rfi_protection_expression" { type = string }

variable "xss_protection_priority" { type = number }
variable "xss_protection_action" { type = string }
variable "xss_protection_preview" {
  type    = bool
  default = true
}
variable "xss_protection_description" { type = string }
variable "xss_protection_expression" { type = string }

variable "sqli_protection_priority" { type = number }
variable "sqli_protection_action" { type = string }
variable "sqli_protection_preview" {
  type    = bool
  default = true
}
variable "sqli_protection_description" { type = string }
variable "sqli_protection_expression" { type = string }

variable "java_rce_protection_priority" { type = number }
variable "java_rce_protection_action" { type = string }
variable "java_rce_protection_preview" {
  type    = bool
  default = true
}
variable "java_rce_protection_description" { type = string }
variable "java_rce_protection_expression" { type = string }

variable "host_localhost_priority" { type = number }
variable "host_localhost_action" { type = string }
variable "host_localhost_preview" {
  type    = bool
  default = true
}
variable "host_localhost_description" { type = string }
variable "host_localhost_expression" { type = string }

variable "propfind_method_priority" { type = number }
variable "propfind_method_action" { type = string }
variable "propfind_method_preview" {
  type    = bool
  default = true
}
variable "propfind_method_description" { type = string }
variable "propfind_method_expression" { type = string }

variable "exploitable_paths_priority" { type = number }
variable "exploitable_paths_action" { type = string }
variable "exploitable_paths_preview" {
  type    = bool
  default = true
}
variable "exploitable_paths_description" { type = string }
variable "exploitable_paths_expression" { type = string }

variable "scanner_detection_priority" { type = number }
variable "scanner_detection_action" { type = string }
variable "scanner_detection_preview" {
  type    = bool
  default = true
}
variable "scanner_detection_description" { type = string }
variable "scanner_detection_expression" { type = string }


variable "invoice_ratelimit_priority" { type = number }
variable "invoice_ratelimit_action" { type = string }
variable "invoice_ratelimit_preview" {
  type    = bool
  default = true
}
variable "invoice_ratelimit_description" { type = string }
variable "invoice_ratelimit_expression" { type = string }

variable "loginotp_priority" { type = number }
variable "loginotp_action" { type = string }
variable "loginotp_preview" {
  type    = bool
  default = true
}
variable "loginotp_description" { type = string }
variable "loginotp_expression" { type = string }

variable "sensitive_paths_priority" { type = number }
variable "sensitive_paths_action" { type = string }
variable "sensitive_paths_preview" {
  type    = bool
  default = true
}
variable "sensitive_paths_description" { type = string }
variable "sensitive_paths_expression" { type = string }

variable "scanning_tool_ua_1_priority" { type = number }
variable "scanning_tool_ua_1_action" { type = string }
variable "scanning_tool_ua_1_preview" {
  type    = bool
  default = true
}
variable "scanning_tool_ua_1_description" { type = string }
variable "scanning_tool_ua_1_expression" { type = string }

variable "scanning_tool_ua_2_priority" { type = number }
variable "scanning_tool_ua_2_action" { type = string }
variable "scanning_tool_ua_2_preview" {
  type    = bool
  default = true
}
variable "scanning_tool_ua_2_description" { type = string }
variable "scanning_tool_ua_2_expression" { type = string }

variable "visibility_endpoints_priority" { type = number }
variable "visibility_endpoints_action" { type = string }
variable "visibility_endpoints_preview" {
  type    = bool
  default = true
}
variable "visibility_endpoints_description" { type = string }
variable "visibility_endpoints_expression" { type = string }

variable "ddos_rate_limit_priority" { type = number }
variable "ddos_rate_limit_action" { type = string }
variable "ddos_rate_limit_preview" {
  type    = bool
  default = true
}
variable "ddos_rate_limit_description" { type = string }
variable "ddos_rate_limit_expression" { type = string }
