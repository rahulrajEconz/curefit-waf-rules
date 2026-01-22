variable "project_id" {
  description = "The GCP project ID"
  type        = string
  default     = "cf-workload-stage"
}

variable "policy_name" {
  description = "The name of the security policy"
  type        = string
}

###########################################
# Toggles (from toggles.tf)
###########################################

variable "enable_allowed_ips" {
  description = "Enable Allowed IPs rule"
  type        = bool
  default     = true
}

variable "enable_scanner_detection" {
  description = "Enable Scanner Detection rule"
  type        = bool
  default     = true
}

variable "enable_java_deserialization" {
  description = "Enable Java Deserialization rule"
  type        = bool
  default     = true
}

variable "enable_localhost_header" {
  description = "Enable Localhost Header rule"
  type        = bool
  default     = true
}

variable "enable_profind_method" {
  description = "Enable PROPFIND Method rule"
  type        = bool
  default     = true
}

variable "enable_exploitable_paths_uripath" {
  description = "Enable Exploitable Paths URI Path rule"
  type        = bool
  default     = true
}

variable "enable_reactjs_rce_body" {
  description = "Enable ReactJS RCE Body rule"
  type        = bool
  default     = true
}

variable "enable_no_user_agent_header" {
  description = "Enable No User Agent Header rule"
  type        = bool
  default     = true
}

variable "enable_sizerestrictions_querystring" {
  description = "Enable Size Restrictions Query String rule"
  type        = bool
  default     = true
}

variable "enable_sizerestrictions_cookie_header" {
  description = "Enable Size Restrictions Cookie Header rule"
  type        = bool
  default     = true
}

variable "enable_sizerestrictions_uripath" {
  description = "Enable Size Restrictions URI Path rule"
  type        = bool
  default     = true
}

variable "enable_ec2_metadata_ssrf" {
  description = "Enable EC2 Metadata SSRF rule"
  type        = bool
  default     = true
}

variable "enable_generic_lfi" {
  description = "Enable Generic LFI rule"
  type        = bool
  default     = true
}

variable "enable_restricted_extensions" {
  description = "Enable Restricted Extensions rule"
  type        = bool
  default     = true
}

variable "enable_generic_rfi" {
  description = "Enable Generic RFI rule"
  type        = bool
  default     = true
}

variable "enable_cross_site_scripting" {
  description = "Enable Cross Site Scripting rule"
  type        = bool
  default     = true
}

###########################################
# Rule Parameters
###########################################

variable "priority_number" { type = number }
variable "rule_action" { type = string }
variable "ip_address_preview" {
  type    = bool
  default = true
}
variable "rule_description" { type = string }
variable "allowed_ip_ranges" { type = list(string) }

variable "scanner_detection_priority" { type = number }
variable "scanner_detection_action" { type = string }
variable "scanner_detection_preview" {
  type    = bool
  default = true
}
variable "scanner_detection_description" { type = string }
variable "scanner_detection_expression" { type = string }

variable "java_deserialization_priority" { type = number }
variable "java_deserialization_action" { type = string }
variable "java_deserialization_preview" {
  type    = bool
  default = true
}
variable "java_deserialization_description" { type = string }
variable "java_deserialization_expression" { type = string }

variable "localhost_header_priority" { type = number }
variable "localhost_HEADER_action" { type = string }
variable "localhost_header_preview" {
  type    = bool
  default = true
}
variable "localhost_header_description" { type = string }
variable "localhost_header_expression" { type = string }

variable "profind_method_priority" { type = number }
variable "profind_method_action" { type = string }
variable "profind_method_preview" {
  type    = bool
  default = true
}
variable "profind_method_description" { type = string }
variable "profind_method_expression" { type = string }

variable "exploitable_paths_uripath_priority" { type = number }
variable "exploitable_paths_uripath_action" { type = string }
variable "exploitable_paths_uripath_preview" {
  type    = bool
  default = true
}
variable "exploitable_paths_uripath_description" { type = string }
variable "exploitable_paths_uripath_expression" { type = string }

variable "reactjs_rce_body_priority" { type = number }
variable "reactjs_rce_body_action" { type = string }
variable "reactjs_rce_body_preview" {
  type    = bool
  default = true
}
variable "reactjs_rce_body_description" { type = string }
variable "reactjs_rce_body_expression" { type = string }

variable "no_user_agent_header_priority" { type = number }
variable "no_user_agent_header_action" { type = string }
variable "no_user_agent_header_preview" {
  type    = bool
  default = true
}
variable "no_user_agent_header_description" { type = string }
variable "no_user_agent_header_expression" { type = string }

variable "sizerestrictions_querystring_priority" { type = number }
variable "sizerestrictions_querystring_action" { type = string }
variable "sizerestrictions_querystring_preview" {
  type    = bool
  default = true
}
variable "sizerestrictions_querystring_description" { type = string }
variable "sizerestrictions_querystring_expression" { type = string }

variable "sizerestrictions_cookie_header_priority" { type = number }
variable "sizerestrictions_cookie_header_action" { type = string }
variable "sizerestrictions_cookie_header_preview" {
  type    = bool
  default = true
}
variable "sizerestrictions_cookie_header_description" { type = string }
variable "sizerestrictions_cookie_header_expression" { type = string }

variable "sizerestrictions_uripath_priority" { type = number }
variable "sizerestrictions_uripath_action" { type = string }
variable "sizerestrictions_uripath_preview" {
  type    = bool
  default = true
}
variable "sizerestrictions_uripath_description" { type = string }
variable "sizerestrictions_uripath_expression" { type = string }

variable "ec2_metadata_ssrf_priority" { type = number }
variable "ec2_metadata_ssrf_action" { type = string }
variable "ec2_metadata_ssrf_preview" {
  type    = bool
  default = true
}
variable "ec2_metadata_ssrf_description" { type = string }
variable "ec2_metadata_ssrf_expression" { type = string }

variable "generic_lfi_priority" { type = number }
variable "generic_lfi_action" { type = string }
variable "generic_lfi_preview" {
  type    = bool
  default = true
}
variable "generic_lfi_description" { type = string }
variable "generic_lfi_expression" { type = string }

variable "restricted_extensions_priority" { type = number }
variable "restricted_extensions_action" { type = string }
variable "restricted_extensions_preview" {
  type    = bool
  default = true
}
variable "restricted_extensions_description" { type = string }
variable "restricted_extensions_expression" { type = string }

variable "generic_rfi_priority" { type = number }
variable "generic_rfi_action" { type = string }
variable "generic_rfi_preview" {
  type    = bool
  default = true
}
variable "generic_rfi_description" { type = string }
variable "generic_rfi_expression" { type = string }

variable "cross_site_scripting_priority" { type = number }
variable "cross_site_scripting_action" { type = string }
variable "cross_site_scripting_preview" {
  type    = bool
  default = true
}
variable "cross_site_scripting_description" { type = string }
variable "cross_site_scripting_expression" { type = string }
