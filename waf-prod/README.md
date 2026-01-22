# WAF Production Policy (waf-prod)

This directory contains the standalone Terraform configuration for the Production Cloud Armor WAF policy.

## Structure
- `main.tf`: Defines the `google_compute_security_policy` and individual `google_compute_security_policy_rule` resources.
- `variables.tf`: Contains all variable definitions, including rule parameters and enable/disable toggles.
- `terraform.tfvars`: Environment-specific values for production.

## Usage
1. Initialize Terraform:
   ```bash
   terraform init
   ```
2. Plan changes:
   ```bash
   terraform plan
   ```
3. Apply changes:
   ```bash
   terraform apply
   ```

## Preview Mode
By default, most rules are set to `preview = true` in `variables.tf` to allow testing before enforcement. You can override this in `terraform.tfvars` or by changing the defaults.
