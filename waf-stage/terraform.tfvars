project_id  = "cf-workload-stage"
policy_name = "terraform-stage-webacl-policy"

rate_limit_priority         = 10
rate_limit_preview          = true
rate_limit_description      = "Rate limit by Source IP - 10000 requests per 5 minutes"
rate_limit_expression       = "true"
rate_limit_count            = 10000
rate_limit_interval_sec     = 300
rate_limit_ban_duration_sec = 300

loginotp_foreign_priority    = 20
loginotp_foreign_action      = "deny(403)"
loginotp_foreign_preview     = true
loginotp_foreign_description = "Block Login OTP requests from non-India traffic"
loginotp_foreign_expression  = "origin.region_code != 'IN' && request.path.contains('loginPhoneSendOtp')"

sendinvoice_priority         = 30
sendinvoice_action           = "rate_based_ban"
sendinvoice_preview          = true
sendinvoice_description      = "Rate limit SendInvoice API by Source IP"
sendinvoice_expression       = "request.path.lower().contains('/sendinvoice')"
sendinvoice_count            = 1000
sendinvoice_interval_sec     = 300
sendinvoice_ban_duration_sec = 300

scanning_ua_priority         = 40
scanning_ua_action           = "rate_based_ban"
scanning_ua_preview          = true
scanning_ua_description      = "Rate limit scanning tools based on User-Agent"
scanning_ua_expression       = "has(request.headers['user-agent']) && (request.headers['user-agent'].lower().contains('nuclei') || request.headers['user-agent'].lower().contains('nmap') || request.headers['user-agent'].lower().contains('sqlmap') || request.headers['user-agent'].lower().contains('nikto'))"
scanning_ua_count            = 500
scanning_ua_interval_sec     = 300
scanning_ua_ban_duration_sec = 600

login_otp_priority         = 50
login_otp_action           = "rate_based_ban"
login_otp_preview          = true
login_otp_description      = "Rate limit loginPhoneSendOtp from India"
login_otp_expression       = "origin.region_code == 'IN' && request.path.contains('/loginPhoneSendOtp')"
login_otp_count            = 5
login_otp_interval_sec     = 60
login_otp_ban_duration_sec = 900
