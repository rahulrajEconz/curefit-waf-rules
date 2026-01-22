provider "google" {
  project = var.project_id
  region  = "global"
}

locals {
  ip_chunks = chunklist(var.allowed_ip_ranges, 10)
}

resource "google_compute_security_policy" "dataplatform-policy" {
  name = var.policy_name
}

############################################
# 1. Allow trusted IPs
############################################
resource "google_compute_security_policy_rule" "allowed_ips" {
  for_each        = var.enable_allowed_ips ? { for i, chunk in local.ip_chunks : i => chunk } : {}
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.priority_number + tonumber(each.key)
  action          = var.rule_action
  preview         = var.ip_address_preview
  description     = "${var.rule_description} (chunk ${tonumber(each.key) + 1})"

  match {
    versioned_expr = "SRC_IPS_V1"
    config {
      src_ip_ranges = each.value
    }
  }
}

############################################
# 2. Scanner Detection
############################################
resource "google_compute_security_policy_rule" "scanner_detection" {
  count           = var.enable_scanner_detection ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
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

############################################
# 3. JavaDeserialization
############################################
resource "google_compute_security_policy_rule" "java_deserialization" {
  count           = var.enable_java_deserialization ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.java_deserialization_priority
  action          = var.java_deserialization_action
  preview         = var.java_deserialization_preview
  description     = var.java_deserialization_description

  match {
    expr {
      expression = var.java_deserialization_expression
    }
  }
}


###########################################
# 5. PROPFIND_METHOD
############################################
resource "google_compute_security_policy_rule" "profind_method" {
  count           = var.enable_profind_method ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.profind_method_priority
  action          = var.profind_method_action
  preview         = var.profind_method_preview
  description     = var.profind_method_description

  match {
    expr {
      expression = var.profind_method_expression
    }
  }
}

###########################################
# 6-14. LFI Protection
###########################################
###########################################
# 6-14. LFI Protection
###########################################
resource "google_compute_security_policy_rule" "lfi_protection" {
  count           = var.enable_lfi_protection ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
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

###########################################
# 7. ReactJSRCE_BODY
############################################
resource "google_compute_security_policy_rule" "reactjs_rce_body" {
  count           = var.enable_reactjs_rce_body ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.reactjs_rce_body_priority
  action          = var.reactjs_rce_body_action
  preview         = var.reactjs_rce_body_preview
  description     = var.reactjs_rce_body_description

  match {
    expr {
      expression = var.reactjs_rce_body_expression
    }
  }
}

###########################################
# 8. NoUserAgent_HEADER
############################################
resource "google_compute_security_policy_rule" "no_user_agent_header" {
  count           = var.enable_no_user_agent_header ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.no_user_agent_header_priority
  action          = var.no_user_agent_header_action
  preview         = var.no_user_agent_header_preview
  description     = var.no_user_agent_header_description

  match {
    expr {
      expression = var.no_user_agent_header_expression
    }
  }
}

############################################
# 9. SizeRestrictions_QUERYSTRING
############################################
resource "google_compute_security_policy_rule" "sizerestrictions_querystring" {
  count           = var.enable_sizerestrictions_querystring ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.sizerestrictions_querystring_priority
  action          = var.sizerestrictions_querystring_action
  preview         = var.sizerestrictions_querystring_preview
  description     = var.sizerestrictions_querystring_description

  match {
    expr {
      expression = var.sizerestrictions_querystring_expression
    }
  }
}

############################################
# 10. SizeRestrictions_Cookie_HEADER
############################################
resource "google_compute_security_policy_rule" "sizerestrictions_cookie_header" {
  count           = var.enable_sizerestrictions_cookie_header ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.sizerestrictions_cookie_header_priority
  action          = var.sizerestrictions_cookie_header_action
  preview         = var.sizerestrictions_cookie_header_preview
  description     = var.sizerestrictions_cookie_header_description

  match {
    expr {
      expression = var.sizerestrictions_cookie_header_expression
    }
  }
}

############################################
# 11. SizeRestrictions_URIPATH
############################################
resource "google_compute_security_policy_rule" "sizerestrictions_uripath" {
  count           = var.enable_sizerestrictions_uripath ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.sizerestrictions_uripath_priority
  action          = var.sizerestrictions_uripath_action
  preview         = var.sizerestrictions_uripath_preview
  description     = var.sizerestrictions_uripath_description

  match {
    expr {
      expression = var.sizerestrictions_uripath_expression
    }
  }
}

############################################
# 12. Protocol Attack Protection (Merged)
############################################
resource "google_compute_security_policy_rule" "protocol_attack_protection" {
  count           = var.enable_protocol_attack_protection ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.protocol_attack_protection_priority
  action          = var.protocol_attack_protection_action
  preview         = var.protocol_attack_protection_preview
  description     = var.protocol_attack_protection_description

  match {
    expr {
      expression = var.protocol_attack_protection_expression
    }
  }
}


############################################
# 15. GenericRFI
############################################
resource "google_compute_security_policy_rule" "generic_rfi" {
  count           = var.enable_generic_rfi ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.generic_rfi_priority
  action          = var.generic_rfi_action
  preview         = var.generic_rfi_preview
  description     = var.generic_rfi_description

  match {
    expr {
      expression = var.generic_rfi_expression
    }
  }
}

############################################
# 16. CrossSiteScripting
############################################
resource "google_compute_security_policy_rule" "cross_site_scripting" {
  count           = var.enable_cross_site_scripting ? 1 : 0
  security_policy = google_compute_security_policy.dataplatform-policy.name
  priority        = var.cross_site_scripting_priority
  action          = var.cross_site_scripting_action
  preview         = var.cross_site_scripting_preview
  description     = var.cross_site_scripting_description

  match {
    expr {
      expression = var.cross_site_scripting_expression
    }
  }
}

############################################
# 17. Default deny
############################################
resource "google_compute_security_policy_rule" "default_deny" {
  security_policy = google_compute_security_policy.dataplatform-policy.name
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
