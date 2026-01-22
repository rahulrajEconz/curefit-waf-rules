# Curefit WAF Terraform 

This repository manages **Google Cloud Armor Security Policies** for various Curefit environments. It uses a flattened architecture where each environment is self-contained.

## Project Structure

The project has been refactored from a modular structure to a standalone, folder-per-environment structure for better isolation and simpler state management.

```text
terraform-curefit/
├── waf-prod/           # Production WAF Policy
├── waf-non-prod/       # Non-Prod (Testing/UAT) WAF Policy
├── waf-dataplatform/   # Data Platform Specific WAF Policy
└── waf-stage/          # Staging Environment WAF Policy
```

### Environment Directories
Each environment folder is independent and contains:
- `main.tf`: Defines the security policy and all individual rule resources.
- `variables.tf`: Consolidates all input variables and rule toggles.
- `terraform.tfvars`: Concrete parameter values (Priorities, Actions, IP ranges).
- `README.md`: Environment-specific documentation and instructions.

## Key Features

- **Individual Rule Management**: Every WAF rule is declared as its own resource, allowing granular control.
- **Rule Toggles**: Enable or disable specific rules using `enable_<rule_name>` boolean variables.
- **Preview Mode**: Rules support `preview = true` for safe testing before enforcement.
- **Standardized Guards**:
    - **Rate Limiting**: Protects against brute force and DDoS.
    - **IP Whitelisting/Blacklisting**: Granular source IP control.
    - **WAF Protections**: SQLi, XSS, LFI, RFI, and Scanner Detection using Cloud Armor's preconfigured rules.
    - **Geographic Blocking**: Ability to block traffic by region.

## Common Operations

To work with a specific environment (e.g., `waf-prod`):

1. **Navigate to the directory**:
   ```bash
   cd waf-prod
   ```

2. **Initialize Terraform**:
   ```bash
   terraform init
   ```

3. **Check current state and plan changes**:
   ```bash
   terraform plan
   ```

4. **Apply changes**:
   ```bash
   terraform apply
   ```

## Design Decisions

- **Action Mapping**: Direct `count` actions are mapped to `deny(403)` with `preview = true` to satisfy Cloud Armor API requirements while maintaining "log-only" functionality.
- **Rate Based Bans**: Rules with ban thresholds (e.g., `slow_rate_limit`) use the `rate_based_ban` action as required by the provider.

