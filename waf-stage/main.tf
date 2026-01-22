provider "google" {
  project = var.project_id
  region  = "global"
}

resource "google_compute_security_policy" "stage-policy" {
  name = var.policy_name
}

###########################################
# 1. Rate Limit Rule – Source IP
###########################################
resource "google_compute_security_policy_rule" "rate_limit" {
  count           = var.enable_rate_limit ? 1 : 0
  security_policy = google_compute_security_policy.stage-policy.name
  priority        = var.rate_limit_priority
  action          = "rate_based_ban"
  preview         = var.rate_limit_preview
  description     = var.rate_limit_description

  match {
    expr {
      expression = var.rate_limit_expression
    }
  }

  rate_limit_options {
    rate_limit_threshold {
      count        = var.rate_limit_count
      interval_sec = var.rate_limit_interval_sec
    }
    ban_duration_sec = var.rate_limit_ban_duration_sec
    conform_action   = "allow"
    exceed_action    = "deny(429)"
    enforce_on_key   = "IP"
  }
}

###########################################
# 2. Login OTP – Foreign Traffic Block
###########################################
resource "google_compute_security_policy_rule" "loginotp_foreign" {
  count           = var.enable_loginotp_foreign ? 1 : 0
  security_policy = google_compute_security_policy.stage-policy.name
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
# 3. SendInvoice – Rate Limit Rule
###########################################
resource "google_compute_security_policy_rule" "sendinvoice" {
  count           = var.enable_sendinvoice ? 1 : 0
  security_policy = google_compute_security_policy.stage-policy.name
  priority        = var.sendinvoice_priority
  action          = var.sendinvoice_action
  preview         = var.sendinvoice_preview
  description     = var.sendinvoice_description

  match {
    expr {
      expression = var.sendinvoice_expression
    }
  }

  rate_limit_options {
    rate_limit_threshold {
      count        = var.sendinvoice_count
      interval_sec = var.sendinvoice_interval_sec
    }
    ban_duration_sec = var.sendinvoice_ban_duration_sec
    conform_action   = "allow"
    exceed_action    = "deny(429)"
    enforce_on_key   = "IP"
  }
}

###########################################
# 4. Scanning Tools User-Agent – Rate Limit
###########################################
resource "google_compute_security_policy_rule" "scanning_ua" {
  count           = var.enable_scanning_ua ? 1 : 0
  security_policy = google_compute_security_policy.stage-policy.name
  priority        = var.scanning_ua_priority
  action          = var.scanning_ua_action
  preview         = var.scanning_ua_preview
  description     = var.scanning_ua_description

  match {
    expr {
      expression = var.scanning_ua_expression
    }
  }

  rate_limit_options {
    rate_limit_threshold {
      count        = var.scanning_ua_count
      interval_sec = var.scanning_ua_interval_sec
    }
    ban_duration_sec = var.scanning_ua_ban_duration_sec
    conform_action   = "allow"
    exceed_action    = "deny(429)"
    enforce_on_key   = "IP"
  }
}

###########################################
# 5. Login OTP – Rate Limit (India only)
###########################################
resource "google_compute_security_policy_rule" "login_otp_india" {
  count           = var.enable_login_otp_india ? 1 : 0
  security_policy = google_compute_security_policy.stage-policy.name
  priority        = var.login_otp_priority
  action          = var.login_otp_action
  preview         = var.login_otp_preview
  description     = var.login_otp_description

  match {
    expr {
      expression = var.login_otp_expression
    }
  }

  rate_limit_options {
    rate_limit_threshold {
      count        = var.login_otp_count
      interval_sec = var.login_otp_interval_sec
    }
    ban_duration_sec = var.login_otp_ban_duration_sec
    conform_action   = "allow"
    exceed_action    = "deny(429)"
    enforce_on_key   = "IP"
  }
}

###########################################
# Default deny
###########################################
resource "google_compute_security_policy_rule" "default_deny" {
  security_policy = google_compute_security_policy.stage-policy.name
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
