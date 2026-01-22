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

variable "enable_rate_limit" {
  description = "Enable Rate Limit rule"
  type        = bool
  default     = true
}

variable "enable_loginotp_foreign" {
  description = "Enable Login OTP Foreign traffic block rule"
  type        = bool
  default     = true
}

variable "enable_sendinvoice" {
  description = "Enable SendInvoice rate limit rule"
  type        = bool
  default     = true
}

variable "enable_scanning_ua" {
  description = "Enable Scanning Tools UA rate limit rule"
  type        = bool
  default     = true
}

variable "enable_login_otp_india" {
  description = "Enable Login OTP India rate limit rule"
  type        = bool
  default     = true
}

###########################################
# Rule Parameters
###########################################

variable "rate_limit_priority" { type = number }
variable "rate_limit_preview" {
  type    = bool
  default = true
}
variable "rate_limit_description" { type = string }
variable "rate_limit_expression" { type = string }
variable "rate_limit_count" { type = number }
variable "rate_limit_interval_sec" { type = number }
variable "rate_limit_ban_duration_sec" { type = number }

variable "loginotp_foreign_priority" { type = number }
variable "loginotp_foreign_action" { type = string }
variable "loginotp_foreign_preview" {
  type    = bool
  default = true
}
variable "loginotp_foreign_description" { type = string }
variable "loginotp_foreign_expression" { type = string }

variable "sendinvoice_priority" { type = number }
variable "sendinvoice_action" { type = string }
variable "sendinvoice_preview" {
  type    = bool
  default = true
}
variable "sendinvoice_description" { type = string }
variable "sendinvoice_expression" { type = string }
variable "sendinvoice_count" { type = number }
variable "sendinvoice_interval_sec" { type = number }
variable "sendinvoice_ban_duration_sec" { type = number }

variable "scanning_ua_priority" { type = number }
variable "scanning_ua_action" { type = string }
variable "scanning_ua_preview" {
  type    = bool
  default = true
}
variable "scanning_ua_description" { type = string }
variable "scanning_ua_expression" { type = string }
variable "scanning_ua_count" { type = number }
variable "scanning_ua_interval_sec" { type = number }
variable "scanning_ua_ban_duration_sec" { type = number }

variable "login_otp_priority" { type = number }
variable "login_otp_action" { type = string }
variable "login_otp_preview" {
  type    = bool
  default = true
}
variable "login_otp_description" { type = string }
variable "login_otp_expression" { type = string }
variable "login_otp_count" { type = number }
variable "login_otp_interval_sec" { type = number }
variable "login_otp_ban_duration_sec" { type = number }

variable "enable_method_enforcement" {
  description = "Enable Method Enforcement rule"
  type        = bool
  default     = true
}

variable "enable_cve_canary" {
  description = "Enable CVE Canary rule"
  type        = bool
  default     = true
}

variable "method_enforcement_priority" { type = number }
variable "method_enforcement_action" { type = string }
variable "method_enforcement_preview" {
  type    = bool
  default = true
}
variable "method_enforcement_description" { type = string }
variable "method_enforcement_expression" { type = string }

variable "cve_canary_priority" { type = number }
variable "cve_canary_action" { type = string }
variable "cve_canary_preview" {
  type    = bool
  default = true
}
variable "cve_canary_description" { type = string }
variable "cve_canary_expression" { type = string }
