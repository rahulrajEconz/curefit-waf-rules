# WAF Stage Configuration

This directory contains the standalone Terraform configuration for the Stage WAF (Cloud Armor) security policy.

## Structure

- `main.tf`: Defines the `google_compute_security_policy` and individual `google_compute_security_policy_rule` resources.
- `variables.tf`: Contains all variable declarations, including rule toggles and parameters.
- `terraform.tfvars`: Environment-specific values for the variables.

## Key Features

- **Flattened Structure**: No longer dependent on external modules or `envs/` directories.
- **Individual Rule Resources**: Each rule is a separate `google_compute_security_policy_rule` for better granularity and state management.
- **Preview Mode**: All rules are set to `preview = true` by default to allow for safe testing.
- **Rule Toggles**: Rules can be enabled/disabled using `enable_<rule_name>` variables in `variables.tf`.

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
