# Terraform Installation and Management Guide



## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Introduction

Terraform is a free and open-source Infrastructure as Code (IaC) tool developed by HashiCorp for building, changing, and versioning infrastructure safely and efficiently across multiple cloud providers. Originally created by Mitchell Hashimoto in 2014, Terraform uses declarative configuration files written in HashiCorp Configuration Language (HCL) to manage infrastructure resources with a declarative approach.

### FOSS Context

As a pure open-source solution, Terraform serves as a powerful alternative to commercial IaC solutions like AWS CloudFormation (AWS-specific), Azure Resource Manager (Azure-specific), or proprietary enterprise tools like Pulumi Enterprise or VMware vRealize. Terraform provides enterprise-grade capabilities without licensing costs:

- **Multi-cloud management** across 3000+ providers
- **State management** with remote backends and locking
- **Extensive provider ecosystem** maintained by HashiCorp and community
- **Team collaboration** features through Terraform Cloud (freemium) or self-hosted alternatives
- **Module system** for reusable infrastructure components
- **Import capabilities** for existing infrastructure
- **Plan and apply workflow** with preview and approval processes

### Key Benefits

- **Vendor neutrality**: Works across all major cloud providers and on-premises systems
- **Declarative syntax**: Define desired state, Terraform handles the implementation
- **Resource graph**: Automatically determines resource dependencies and creation order
- **State tracking**: Maintains current infrastructure state for accurate change management
- **Immutable infrastructure**: Encourages infrastructure replacement rather than modification
- **Community support**: Large ecosystem with extensive documentation and community modules

## 2. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for large infrastructures)
  - RAM: 2GB minimum (4GB+ recommended for production)
  - Storage: 5GB minimum (more for state files and provider binaries)
  - Network: Stable connectivity for cloud provider APIs
- **Operating System**: 
  - Linux: Any modern distribution with kernel 3.2+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 12.0+
- **Network Requirements**:
  - HTTPS access to cloud provider APIs (port 443)
  - Access to Terraform Registry (registry.terraform.io)
  - Access to HashiCorp releases (releases.hashicorp.com)
- **Dependencies**:
  - Cloud provider CLI tools (aws-cli, azure-cli, gcloud)
  - Git for configuration management
  - Text editor or IDE
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required for installation

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Add HashiCorp repository
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo

# Install Terraform
sudo yum install -y terraform

# Verify installation
terraform version

# Alternative: DNF for newer systems
sudo dnf install -y yum-utils
sudo dnf config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo
sudo dnf install -y terraform
```

### Debian/Ubuntu

```bash
# Add HashiCorp GPG key
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

# Add HashiCorp repository
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

# Update and install Terraform
sudo apt update
sudo apt install -y terraform

# Verify installation
terraform version
```

### Arch Linux

```bash
# Install from community repository
sudo pacman -S terraform

# Alternative: Install from AUR
yay -S terraform

# Install additional tools
sudo pacman -S terraform-docs tflint

# Verify installation
terraform version
```

### Alpine Linux

```bash
# Install from Alpine repositories
sudo apk update
sudo apk add terraform

# Install additional tools
sudo apk add bash git curl

# Verify installation
terraform version
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y terraform

# SLES 15
sudo SUSEConnect -p sle-module-development-tools/15.5/x86_64
sudo zypper install -y terraform

# Alternative: Add HashiCorp repository
sudo zypper addrepo https://rpm.releases.hashicorp.com/SLES/hashicorp.repo
sudo zypper refresh
sudo zypper install terraform

# Verify installation
terraform version
```

### macOS

```bash
# Using Homebrew
brew tap hashicorp/tap
brew install hashicorp/tap/terraform

# Alternative: Install specific version
brew install terraform@1.6

# Verify installation
terraform version

# Using tfenv for version management
brew install tfenv
tfenv install latest
tfenv use latest
```

### FreeBSD

```bash
# Using pkg
pkg install terraform

# Using ports
cd /usr/ports/sysutils/terraform
make install clean

# Verify installation
terraform version
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install terraform

# Method 2: Using Scoop
scoop bucket add main
scoop install terraform

# Method 3: Manual installation
# Download from https://releases.hashicorp.com/terraform/
# Extract terraform.exe to C:\terraform
# Add C:\terraform to PATH

# Method 4: Using Winget
winget install HashiCorp.Terraform

# Verify installation
terraform version
```

## 4. Initial Configuration

### First-Run Setup

1. **Create terraform user** (optional for dedicated service):
```bash
# Linux systems
sudo useradd -r -d /opt/terraform -s /sbin/nologin -c "Terraform Service" terraform
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/terraform/` (custom) or `/usr/local/bin/`
- Debian/Ubuntu: `/etc/terraform/` (custom) or `/usr/local/bin/`
- Arch Linux: `/etc/terraform/` (custom) or `/usr/bin/`
- Alpine Linux: `/etc/terraform/` (custom) or `/usr/bin/`
- openSUSE/SLES: `/etc/terraform/` (custom) or `/usr/local/bin/`
- macOS: `/usr/local/etc/terraform/` or `/opt/homebrew/etc/terraform/`
- FreeBSD: `/usr/local/etc/terraform/`
- Windows: `C:\terraform\` or `%APPDATA%\terraform\`

3. **Essential initial configuration**:

```bash
# Create workspace directory
mkdir -p ~/terraform/projects
cd ~/terraform/projects

# Create first Terraform configuration
cat > main.tf <<EOF
terraform {
  required_version = ">= 1.6"
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
  }
}

resource "local_file" "hello_world" {
  content  = "Hello, World from Terraform!"
  filename = "hello.txt"
}
EOF

# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan

# Apply configuration
terraform apply
```

### Testing Initial Setup

```bash
# Check Terraform version
terraform version

# Validate configuration
terraform validate

# Format configuration files
terraform fmt

# Initialize and test basic functionality
terraform init
terraform plan
terraform apply

# List state
terraform state list

# Show state details
terraform show

# Clean up test resources
terraform destroy
```

**WARNING:** Configure proper authentication for cloud providers before deploying real infrastructure!

## 5. Service Management

### systemd (Linux Systems)

```bash
# Create systemd service for Terraform agent (if using)
sudo tee /etc/systemd/system/terraform-agent.service <<EOF
[Unit]
Description=Terraform Agent
After=network.target

[Service]
Type=simple
User=terraform
WorkingDirectory=/opt/terraform
ExecStart=/usr/local/bin/terraform-agent
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable terraform-agent
```

### OpenRC (Alpine Linux)

```bash
# Create OpenRC service script
sudo tee /etc/init.d/terraform-agent <<EOF
#!/sbin/openrc-run

name="terraform-agent"
description="Terraform Agent"
command="/usr/bin/terraform-agent"
command_user="terraform"
command_background=true
pidfile="/var/run/terraform-agent.pid"

depend() {
    need net
}
EOF

sudo chmod +x /etc/init.d/terraform-agent
rc-update add terraform-agent default
```

### rc.d (FreeBSD)

```bash
# Create rc.d script
sudo tee /usr/local/etc/rc.d/terraform_agent <<EOF
#!/bin/sh
. /etc/rc.subr

name=terraform_agent
rcvar=terraform_agent_enable
command="/usr/local/bin/terraform-agent"
pidfile="/var/run/terraform_agent.pid"
start_cmd="terraform_agent_start"

terraform_agent_start() {
    daemon -p \${pidfile} \${command}
}

load_rc_config \$name
run_rc_command "\$1"
EOF

sudo chmod +x /usr/local/etc/rc.d/terraform_agent
echo 'terraform_agent_enable="YES"' >> /etc/rc.conf
```

### launchd (macOS)

```bash
# Create LaunchDaemon plist
sudo tee /Library/LaunchDaemons/com.hashicorp.terraform.agent.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hashicorp.terraform.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/terraform-agent</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.hashicorp.terraform.agent.plist
```

### Windows Service Manager

```powershell
# Install Terraform as Windows service using NSSM
nssm install TerraformAgent "C:\terraform\terraform-agent.exe"
nssm set TerraformAgent AppDirectory "C:\terraform"
nssm set TerraformAgent DisplayName "Terraform Agent"
nssm set TerraformAgent Description "HashiCorp Terraform Agent"
nssm start TerraformAgent

# Alternative: Using sc command
sc create TerraformAgent binPath="C:\terraform\terraform-agent.exe" start=auto
sc start TerraformAgent
```

## 6. Advanced Configuration

### Multi-Cloud Provider Setup

```bash
# Create comprehensive multi-cloud configuration
cat > providers.tf <<EOF
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
  
  # Remote state configuration
  backend "s3" {
    bucket = "terraform-state-bucket"
    key    = "infrastructure/terraform.tfstate"
    region = "us-west-2"
    
    # State locking with DynamoDB
    dynamodb_table = "terraform-state-lock"
    encrypt        = true
  }
}

# AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment   = var.environment
      ManagedBy     = "terraform"
      Project       = var.project_name
      Owner         = var.owner
    }
  }
}

# Azure Provider
provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

# Google Cloud Provider
provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
  zone    = var.gcp_zone
}

# Kubernetes Provider
provider "kubernetes" {
  config_path = "~/.kube/config"
}

# Helm Provider
provider "helm" {
  kubernetes {
    config_path = "~/.kube/config"
  }
}
EOF
```

### Enterprise Features Configuration

```bash
# Terraform Cloud/Enterprise configuration
cat > cloud.tf <<EOF
terraform {
  cloud {
    organization = "your-organization"
    
    workspaces {
      name = "production-infrastructure"
    }
  }
}

# Remote execution configuration
terraform {
  cloud {
    organization = "your-organization"
    
    workspaces {
      tags = ["production", "web-app"]
    }
  }
  
  required_providers {
    tfe = {
      source  = "hashicorp/tfe"
      version = "~> 0.48"
    }
  }
}

# Terraform Enterprise configuration
provider "tfe" {
  hostname = "terraform.company.com"
  token    = var.tfe_token
}

# Workspace configuration
resource "tfe_workspace" "production" {
  name         = "production-infrastructure"
  organization = var.tfe_organization
  
  auto_apply = false
  queue_all_runs = false
  
  terraform_version = "1.6.4"
  
  vcs_repo {
    identifier     = "company/infrastructure"
    branch         = "main"
    oauth_token_id = var.vcs_oauth_token_id
  }
  
  working_directory = "environments/production"
}
EOF
```

### Advanced State Management

```bash
# Encrypted remote state with multiple backends
cat > backend-s3.tf <<EOF
# S3 backend with encryption and locking
terraform {
  backend "s3" {
    bucket         = "terraform-state-bucket"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-west-2"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:us-west-2:ACCOUNT:key/KEY-ID"
    dynamodb_table = "terraform-state-lock"
    
    # Additional security
    skip_region_validation      = false
    skip_credentials_validation = false
    skip_metadata_api_check     = false
  }
}

# State bucket with versioning and lifecycle
resource "aws_s3_bucket" "terraform_state" {
  bucket = "terraform-state-bucket"
  
  tags = {
    Name        = "Terraform State Bucket"
    Environment = var.environment
  }
}

resource "aws_s3_bucket_versioning" "terraform_state_versioning" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state_encryption" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.terraform_bucket_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for encryption
resource "aws_kms_key" "terraform_bucket_key" {
  description             = "KMS key for Terraform state bucket encryption"
  deletion_window_in_days = 7

  tags = {
    Name        = "Terraform State Bucket Key"
    Environment = var.environment
  }
}

# DynamoDB table for state locking
resource "aws_dynamodb_table" "terraform_state_lock" {
  name           = "terraform-state-lock"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Name        = "Terraform State Lock Table"
    Environment = var.environment
  }
}
EOF
```

### Terraform Workspaces and Environment Management

```bash
# Enterprise workspace management
cat > workspace-management.tf <<EOF
# Workspace-specific variables
variable "workspace_configs" {
  description = "Configuration per workspace"
  type = map(object({
    instance_type    = string
    min_size        = number
    max_size        = number
    environment_tag = string
    backup_retention = number
    monitoring_level = string
  }))
  default = {
    development = {
      instance_type    = "t3.micro"
      min_size        = 1
      max_size        = 3
      environment_tag = "dev"
      backup_retention = 7
      monitoring_level = "basic"
    }
    staging = {
      instance_type    = "t3.small"
      min_size        = 2
      max_size        = 5
      environment_tag = "staging"
      backup_retention = 14
      monitoring_level = "standard"
    }
    production = {
      instance_type    = "m5.large"
      min_size        = 3
      max_size        = 10
      environment_tag = "prod"
      backup_retention = 30
      monitoring_level = "comprehensive"
    }
  }
}

# Current workspace configuration
locals {
  workspace_config = var.workspace_configs[terraform.workspace]
  
  common_tags = {
    Environment   = local.workspace_config.environment_tag
    Workspace     = terraform.workspace
    Project       = var.project_name
    ManagedBy     = "terraform"
    Owner         = var.owner
    CostCenter    = var.cost_center
    Compliance    = var.compliance_level
  }
}

# Workspace-aware resource sizing
resource "aws_launch_template" "web_servers" {
  name_prefix   = "${var.project_name}-${terraform.workspace}-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = local.workspace_config.instance_type
  
  vpc_security_group_ids = [aws_security_group.web.id]
  
  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    environment = terraform.workspace
    log_level   = local.workspace_config.monitoring_level
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags          = local.common_tags
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Auto-scaling based on workspace
resource "aws_autoscaling_group" "web" {
  name                = "${var.project_name}-${terraform.workspace}-asg"
  vpc_zone_identifier = var.private_subnet_ids
  target_group_arns   = [aws_lb_target_group.web.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = local.workspace_config.min_size
  max_size         = local.workspace_config.max_size
  desired_capacity = local.workspace_config.min_size

  launch_template {
    id      = aws_launch_template.web_servers.id
    version = "$Latest"
  }
  
  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
}
EOF

# Workspace management commands
cat > scripts/workspace-management.sh <<'EOF'
#!/bin/bash

# List all workspaces with their status
list_workspaces() {
    echo "📋 Terraform Workspaces:"
    terraform workspace list
    echo ""
    echo "Current workspace: $(terraform workspace show)"
}

# Create new workspace with initialization
create_workspace() {
    local workspace_name="$1"
    
    if [[ -z "$workspace_name" ]]; then
        echo "Usage: create_workspace <workspace-name>"
        return 1
    fi
    
    echo "🚀 Creating workspace: $workspace_name"
    terraform workspace new "$workspace_name"
    terraform workspace select "$workspace_name"
    
    # Initialize with workspace-specific variables
    if [[ ! -f "$workspace_name.tfvars" ]]; then
        echo "Creating $workspace_name.tfvars template..."
        cat > "$workspace_name.tfvars" <<VARS
# Workspace-specific variables for $workspace_name
project_name = "myproject-$workspace_name"
environment = "$workspace_name"
owner = "$(whoami)"
cost_center = "engineering"
compliance_level = "standard"

# Network configuration
vpc_cidr = "10.0.0.0/16"
availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]

# Resource sizing (adjust per environment)
instance_type = "t3.micro"
min_capacity = 1
max_capacity = 3
VARS
        echo "✅ Template created at $workspace_name.tfvars"
        echo "💡 Please review and customize the variables before applying"
    fi
}

# Switch workspace with validation
switch_workspace() {
    local workspace_name="$1"
    
    if [[ -z "$workspace_name" ]]; then
        echo "Usage: switch_workspace <workspace-name>"
        return 1
    fi
    
    if terraform workspace list | grep -q "\b$workspace_name\b"; then
        terraform workspace select "$workspace_name"
        echo "✅ Switched to workspace: $workspace_name"
        
        # Show current configuration
        echo "📄 Current configuration file: $workspace_name.tfvars"
        if [[ -f "$workspace_name.tfvars" ]]; then
            echo "✅ Variables file exists"
        else
            echo "⚠️  Variables file missing - creating template"
            create_workspace "$workspace_name"
        fi
    else
        echo "❌ Workspace '$workspace_name' not found"
        echo "Available workspaces:"
        terraform workspace list
    fi
}

# Delete workspace with safety checks
delete_workspace() {
    local workspace_name="$1"
    
    if [[ -z "$workspace_name" ]]; then
        echo "Usage: delete_workspace <workspace-name>"
        return 1
    fi
    
    if [[ "$workspace_name" == "default" ]]; then
        echo "❌ Cannot delete the default workspace"
        return 1
    fi
    
    echo "⚠️  WARNING: This will delete workspace '$workspace_name' and all its resources!"
    echo "Current resources in workspace:"
    
    # Switch to workspace and show resources
    terraform workspace select "$workspace_name"
    terraform state list
    
    echo ""
    read -p "Are you sure you want to proceed? (yes/no): " confirm
    
    if [[ "$confirm" == "yes" ]]; then
        echo "🗑️  Destroying resources in workspace: $workspace_name"
        terraform destroy -auto-approve -var-file="$workspace_name.tfvars"
        
        echo "🗑️  Deleting workspace: $workspace_name"
        terraform workspace select default
        terraform workspace delete "$workspace_name"
        
        echo "✅ Workspace '$workspace_name' deleted"
    else
        echo "❌ Operation cancelled"
    fi
}

# Main command dispatcher
case "${1:-help}" in
    "list")
        list_workspaces
        ;;
    "create")
        create_workspace "$2"
        ;;
    "switch")
        switch_workspace "$2"
        ;;
    "delete")
        delete_workspace "$2"
        ;;
    "help"|*)
        echo "Terraform Workspace Management"
        echo "Usage: $0 [list|create|switch|delete] [workspace-name]"
        echo ""
        echo "Commands:"
        echo "  list                    - List all workspaces"
        echo "  create <name>          - Create new workspace with template"
        echo "  switch <name>          - Switch to existing workspace"
        echo "  delete <name>          - Delete workspace and all resources"
        ;;
esac
EOF

chmod +x scripts/workspace-management.sh
```

### Remote State Configuration Best Practices

```bash
# Enterprise remote state configuration
cat > remote-state-setup.tf <<EOF
# Multi-environment state configuration
terraform {
  backend "s3" {
    # Use workspace-aware state keys
    key            = "infrastructure/\${terraform.workspace}/terraform.tfstate"
    bucket         = var.state_bucket_name
    region         = var.aws_region
    encrypt        = true
    kms_key_id     = var.state_kms_key_arn
    dynamodb_table = var.state_lock_table
    
    # Workspace isolation
    workspace_key_prefix = "workspaces"
  }
}

# State bucket with advanced features
resource "aws_s3_bucket" "terraform_state" {
  bucket        = var.state_bucket_name
  force_destroy = false  # Prevent accidental deletion
  
  tags = {
    Name            = "Terraform State Bucket"
    Purpose         = "Infrastructure State Storage"
    Environment     = "global"
    BackupRequired  = "true"
    ComplianceLevel = "high"
  }
}

# Cross-region replication for disaster recovery
resource "aws_s3_bucket_replication_configuration" "terraform_state_replication" {
  role   = aws_iam_role.replication.arn
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    id     = "terraform-state-replication"
    status = "Enabled"
    
    filter {
      prefix = "workspaces/"
    }

    destination {
      bucket        = aws_s3_bucket.terraform_state_replica.arn
      storage_class = "STANDARD_IA"
      
      encryption_configuration {
        replica_kms_key_id = aws_kms_key.terraform_state_replica.arn
      }
    }
  }
}

# Lifecycle management for cost optimization
resource "aws_s3_bucket_lifecycle_configuration" "terraform_state_lifecycle" {
  bucket = aws_s3_bucket.terraform_state.id

  rule {
    id     = "state_file_lifecycle"
    status = "Enabled"

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_transition {
      noncurrent_days = 90
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# Advanced DynamoDB table for state locking with point-in-time recovery
resource "aws_dynamodb_table" "terraform_state_lock" {
  name           = var.state_lock_table
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "LockID"
  
  attribute {
    name = "LockID"
    type = "S"
  }

  # Enable point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # Server-side encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.terraform_state.arn
  }

  # Enable continuous backups
  tags = {
    Name           = "Terraform State Lock"
    BackupRequired = "true"
    Environment    = "global"
  }
}

# CloudWatch alarms for state operations
resource "aws_cloudwatch_metric_alarm" "state_bucket_errors" {
  alarm_name          = "terraform-state-bucket-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4xxErrors"
  namespace           = "AWS/S3"
  period              = "300"
  statistic           = "Sum"
  threshold           = "5"
  alarm_description   = "This metric monitors S3 bucket errors for Terraform state"

  dimensions = {
    BucketName = aws_s3_bucket.terraform_state.bucket
  }

  alarm_actions = [aws_sns_topic.infrastructure_alerts.arn]
}
EOF
```

## 7. Reverse Proxy Setup

Terraform itself doesn't typically require reverse proxy setup, but when using Terraform Enterprise or Cloud, you might need to configure proxies for API access:

### Corporate Proxy Configuration

```bash
# Configure Terraform to work through corporate proxy
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.company.com

# Add to ~/.bashrc or ~/.zshrc
cat >> ~/.bashrc <<EOF
# Terraform proxy settings
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.company.com
EOF

# Configure Git for proxy (if needed for modules)
git config --global http.proxy http://proxy.company.com:8080
git config --global https.proxy http://proxy.company.com:8080
```

### nginx Configuration for Terraform Enterprise

```nginx
# /etc/nginx/sites-available/terraform-enterprise
upstream terraform_enterprise {
    server 127.0.0.1:8800;
    server 127.0.0.1:8801 backup;
}

server {
    listen 443 ssl http2;
    server_name terraform.company.com;

    ssl_certificate /etc/ssl/certs/terraform.company.com.crt;
    ssl_certificate_key /etc/ssl/private/terraform.company.com.key;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        proxy_pass http://terraform_enterprise;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for real-time updates
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts for long-running operations
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 300s;
    }
}
```

## 8. Security Configuration

### Secure Credential Management

```bash
# Use environment variables for credentials
cat > .env.example <<EOF
# AWS credentials
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-west-2

# Azure credentials
ARM_CLIENT_ID=your_client_id
ARM_CLIENT_SECRET=your_client_secret
ARM_SUBSCRIPTION_ID=your_subscription_id
ARM_TENANT_ID=your_tenant_id

# GCP credentials
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
GOOGLE_PROJECT=your_project_id

# Terraform Cloud
TF_CLOUD_TOKEN=your_terraform_cloud_token
EOF

# Use IAM roles for AWS (recommended)
cat > aws-iam-role.tf <<EOF
# IAM role for Terraform execution
resource "aws_iam_role" "terraform_execution" {
  name = "TerraformExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# Attach managed policies with least privilege
resource "aws_iam_role_policy_attachment" "terraform_execution" {
  for_each = toset([
    "arn:aws:iam::aws:policy/PowerUserAccess"
  ])
  
  role       = aws_iam_role.terraform_execution.name
  policy_arn = each.value
}

# Create instance profile
resource "aws_iam_instance_profile" "terraform_execution" {
  name = "TerraformExecutionProfile"
  role = aws_iam_role.terraform_execution.name
}
EOF
```

### Security Scanning and Compliance

```bash
# Pre-commit hooks for security
cat > .pre-commit-config.yaml <<EOF
repos:
- repo: https://github.com/antonbabenko/pre-commit-terraform
  rev: v1.83.5
  hooks:
    - id: terraform_fmt
    - id: terraform_validate
    - id: terraform_docs
    - id: terraform_tflint
    - id: terraform_checkov
    - id: terraform_trivy

- repo: https://github.com/Yelp/detect-secrets
  rev: v1.4.0
  hooks:
    - id: detect-secrets
      args: ['--baseline', '.secrets.baseline']
EOF

# Checkov configuration for security scanning
cat > .checkov.yaml <<EOF
framework:
  - terraform
  - secrets

check:
  - CKV_AWS_79  # Ensure Instance Metadata Service Version 1 is not enabled
  - CKV_AWS_8   # Ensure Launch Configuration EBS encryption
  - CKV_AZURE_1 # Ensure storage account encryption

skip-check:
  - CKV_AWS_23  # Skip S3 bucket public read check for specific use cases

output: cli
quiet: false
compact: false
EOF

# TFLint configuration
cat > .tflint.hcl <<EOF
plugin "aws" {
    enabled = true
    version = "0.21.2"
    source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

plugin "azurerm" {
    enabled = true
    version = "0.21.0"
    source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

rule "terraform_unused_declarations" {
  enabled = true
}

rule "terraform_naming_convention" {
  enabled = true
  format  = "snake_case"
}
EOF
```

### Policy as Code with OPA

```bash
# OPA (Open Policy Agent) security policies
cat > policy/security.rego <<EOF
package terraform.security

# Deny instances without encryption
deny[reason] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    resource.change.after.root_block_device[_].encrypted == false
    reason := "AWS instances must have encrypted root volumes"
}

# Deny public S3 buckets
deny[reason] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.after.block_public_acls == false
    reason := "S3 buckets must block public access"
}

# Require specific instance types in production
deny[reason] {
    resource := input.resource_changes[_]
    resource.type == "aws_instance"
    instance_type := resource.change.after.instance_type
    not allowed_instance_type(instance_type)
    workspace := input.terraform_version.workspace
    workspace == "production"
    reason := sprintf("Production instances must use approved instance types, got: %v", [instance_type])
}

allowed_instance_type(instance_type) {
    allowed_types := ["t3.micro", "t3.small", "t3.medium", "m5.large", "m5.xlarge"]
    instance_type in allowed_types
}
EOF

# Policy validation script
cat > scripts/validate-policy.sh <<'EOF'
#!/bin/bash

# Generate Terraform plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Validate against policies
conftest test tfplan.json --policy policy/

# Cleanup
rm tfplan tfplan.json
EOF

chmod +x scripts/validate-policy.sh
```

## 9. Database Setup

Terraform doesn't require a traditional database, but it does use state files and can integrate with various storage backends:

### State Storage Backends

```bash
# PostgreSQL backend (for Terraform Enterprise)
cat > backend-postgres.tf <<EOF
terraform {
  backend "pg" {
    conn_str = "postgres://user:pass@localhost/terraform_backend?sslmode=require"
  }
}
EOF

# Consul backend for distributed state
cat > backend-consul.tf <<EOF
terraform {
  backend "consul" {
    address = "consul.company.com:8500"
    scheme  = "https"
    path    = "terraform/infrastructure"
  }
}
EOF

# etcd backend
cat > backend-etcd.tf <<EOF
terraform {
  backend "etcdv3" {
    endpoints = ["http://etcd1:2379", "http://etcd2:2379", "http://etcd3:2379"]
    lock      = true
    prefix    = "terraform-state/"
  }
}
EOF
```

### Database Infrastructure Management

```bash
# Database deployment with Terraform
cat > database.tf <<EOF
# RDS instance with Multi-AZ
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-db"
  
  engine         = "postgresql"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id          = aws_kms_key.rds.arn
  
  db_name  = var.database_name
  username = var.database_username
  password = var.database_password
  port     = 5432
  
  multi_az               = true
  publicly_accessible    = false
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-db-final-snapshot"
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  tags = var.common_tags
}

# Database subnet group
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-db-subnet-group"
  })
}

# KMS key for RDS encryption
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7

  tags = merge(var.common_tags, {
    Name = "${var.project_name}-rds-kms-key"
  })
}
EOF
```

## 10. Performance Optimization

### Terraform Performance Tuning

```bash
# Optimize Terraform execution
cat > terraform.tfvars <<EOF
# Performance settings
terraform_parallelism = 10
terraform_refresh = true
terraform_upgrade = false
EOF

# Performance optimization script
cat > scripts/optimize-terraform.sh <<'EOF'
#!/bin/bash

# Increase parallelism for faster execution
export TF_CLI_ARGS_plan="-parallelism=10"
export TF_CLI_ARGS_apply="-parallelism=10"

# Use faster JSON output for large states
export TF_CLI_ARGS_show="-json"

# Optimize provider caching
export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"
mkdir -p "$TF_PLUGIN_CACHE_DIR"

# Performance monitoring
echo "Starting Terraform operation at $(date)"
time terraform "$@"
echo "Completed Terraform operation at $(date)"
EOF

chmod +x scripts/optimize-terraform.sh
```

### Large Infrastructure Management

```bash
# Workspace and module organization
cat > modules/infrastructure/main.tf <<EOF
# Optimized module structure for large deployments
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Use data sources efficiently
data "aws_availability_zones" "available" {
  state = "available"
  
  # Cache this data to avoid repeated API calls
  lifecycle {
    postcondition {
      condition     = length(self.names) >= 2
      error_message = "At least 2 availability zones required."
    }
  }
}

# Optimize resource creation with for_each
resource "aws_subnet" "private" {
  for_each = toset(slice(data.aws_availability_zones.available.names, 0, var.subnet_count))
  
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, index(data.aws_availability_zones.available.names, each.value) + 10)
  availability_zone = each.value
  
  tags = merge(var.common_tags, {
    Name = "${var.name_prefix}-private-${each.value}"
    Type = "private"
  })
}

# Use locals for complex computations
locals {
  # Pre-compute values to avoid recalculation
  availability_zones = slice(data.aws_availability_zones.available.names, 0, var.subnet_count)
  
  # Create maps for efficient lookups
  subnet_map = {
    for subnet in aws_subnet.private : 
    subnet.availability_zone => subnet.id
  }
}
EOF
```

### State Optimization

```bash
# State file optimization script
cat > scripts/optimize-state.sh <<'EOF'
#!/bin/bash

# Pull current state for backup
terraform state pull > state-backup-$(date +%Y%m%d_%H%M%S).json

# Remove unused resources from state
terraform state list | while read resource; do
    if terraform plan -target="$resource" | grep -q "No changes"; then
        echo "Checking if $resource can be safely removed..."
        # Add logic to safely remove unused resources
    fi
done

# Refresh state to sync with real infrastructure
terraform refresh

echo "State optimization completed"
EOF

chmod +x scripts/optimize-state.sh
```

## 11. Monitoring

### Terraform Operations Monitoring

```bash
# Terraform execution monitoring
cat > scripts/monitor-terraform.sh <<'EOF'
#!/bin/bash

LOG_FILE="/var/log/terraform/operations.log"
METRICS_FILE="/var/log/terraform/metrics.log"

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$METRICS_FILE")"

# Function to log operations
log_operation() {
    local operation="$1"
    local status="$2"
    local duration="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] Operation: $operation, Status: $status, Duration: ${duration}s" >> "$LOG_FILE"
    echo "terraform_operation_duration{operation=\"$operation\",status=\"$status\"} $duration" >> "$METRICS_FILE"
}

# Wrapper function for terraform commands
terraform_monitored() {
    local operation="$1"
    shift
    local start_time=$(date +%s)
    local exit_code=0
    
    echo "Starting Terraform $operation at $(date)"
    
    if terraform "$operation" "$@"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_operation "$operation" "success" "$duration"
        echo "Terraform $operation completed successfully in ${duration}s"
    else
        exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        log_operation "$operation" "failure" "$duration"
        echo "Terraform $operation failed after ${duration}s"
        return $exit_code
    fi
}

# Usage: terraform_monitored plan, terraform_monitored apply, etc.
terraform_monitored "$@"
EOF

chmod +x scripts/monitor-terraform.sh
```

### Infrastructure Monitoring with Terraform

```bash
# Deploy monitoring stack with Terraform
cat > monitoring.tf <<EOF
# CloudWatch alarms for infrastructure
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  for_each = toset(module.compute.instance_ids)
  
  alarm_name          = "high-cpu-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  period             = "300"
  statistic          = "Average"
  threshold          = "80"
  alarm_description  = "This metric monitors EC2 CPU utilization"

  dimensions = {
    InstanceId = each.value
  }

  alarm_actions = [aws_sns_topic.alerts.arn]
  
  tags = var.common_tags
}

# SNS topic for alerts
resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-infrastructure-alerts"
  
  tags = var.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Log group for Terraform operations
resource "aws_cloudwatch_log_group" "terraform_ops" {
  name              = "/terraform/operations"
  retention_in_days = 30
  
  tags = var.common_tags
}

# Dashboard for infrastructure monitoring
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-infrastructure"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", module.compute.instance_ids[0]],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "EC2 Instance CPU"
          period  = 300
        }
      }
    ]
  })
}
EOF
```

### Terraform Cloud Monitoring

```bash
# Monitor Terraform Cloud workspaces
cat > scripts/monitor-tf-cloud.sh <<'EOF'
#!/bin/bash

TF_CLOUD_TOKEN="${TF_CLOUD_TOKEN}"
ORGANIZATION="${TF_ORGANIZATION}"

# Function to get workspace status
get_workspace_status() {
    local workspace_name="$1"
    
    curl -s \
        --header "Authorization: Bearer $TF_CLOUD_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/organizations/$ORGANIZATION/workspaces/$workspace_name/current-run" \
        | jq -r '.data.attributes.status'
}

# Function to get workspace runs
get_recent_runs() {
    local workspace_id="$1"
    
    curl -s \
        --header "Authorization: Bearer $TF_CLOUD_TOKEN" \
        --header "Content-Type: application/vnd.api+json" \
        "https://app.terraform.io/api/v2/workspaces/$workspace_id/runs" \
        | jq -r '.data[].attributes | "\(.status) - \(.created_at)"'
}

# Monitor critical workspaces
WORKSPACES=("production-web" "production-database" "staging-environment")

for workspace in "${WORKSPACES[@]}"; do
    status=$(get_workspace_status "$workspace")
    echo "Workspace: $workspace, Status: $status"
    
    if [[ "$status" == "errored" ]]; then
        echo "❌ ALERT: Workspace $workspace has errors!"
        # Send alert to monitoring system
        curl -X POST \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"Terraform workspace $workspace has errors\"}" \
            "$SLACK_WEBHOOK_URL"
    elif [[ "$status" == "planned_and_finished" ]]; then
        echo "✅ Workspace $workspace is healthy"
    fi
done
EOF

chmod +x scripts/monitor-tf-cloud.sh
```

## 12. Backup and Restore

### State File Backup

```bash
# Comprehensive state backup script
cat > scripts/backup-terraform-state.sh <<'EOF'
#!/bin/bash

BACKUP_DIR="/backup/terraform"
DATE=$(date +%Y%m%d_%H%M%S)
ENVIRONMENTS=("development" "staging" "production")

mkdir -p "$BACKUP_DIR"

backup_state() {
    local environment="$1"
    local backup_path="$BACKUP_DIR/$environment"
    
    echo "Backing up $environment state..."
    mkdir -p "$backup_path"
    
    # Change to environment directory
    cd "environments/$environment" || return 1
    
    # Pull current state
    terraform state pull > "$backup_path/terraform-state-$DATE.json"
    
    # Backup configuration files
    tar -czf "$backup_path/terraform-config-$DATE.tar.gz" \
        --exclude=".terraform" \
        --exclude="*.tfplan" \
        .
    
    # Backup workspace info
    terraform workspace show > "$backup_path/current-workspace-$DATE.txt"
    terraform workspace list > "$backup_path/all-workspaces-$DATE.txt"
    
    # Backup provider versions
    terraform version > "$backup_path/terraform-version-$DATE.txt"
    
    cd - > /dev/null
    
    echo "✅ Backup completed for $environment"
}

# Backup all environments
for env in "${ENVIRONMENTS[@]}"; do
    if [[ -d "environments/$env" ]]; then
        backup_state "$env"
    else
        echo "⚠️  Environment directory not found: environments/$env"
    fi
done

# Create consolidated backup
cd "$BACKUP_DIR"
tar -czf "terraform-complete-backup-$DATE.tar.gz" \
    --exclude="*.tar.gz" \
    .

# Upload to cloud storage
if command -v aws &> /dev/null; then
    aws s3 cp "terraform-complete-backup-$DATE.tar.gz" \
        s3://terraform-backups/
fi

if command -v az &> /dev/null; then
    az storage blob upload \
        --file "terraform-complete-backup-$DATE.tar.gz" \
        --container-name terraform-backups \
        --name "terraform-complete-backup-$DATE.tar.gz"
fi

if command -v gsutil &> /dev/null; then
    gsutil cp "terraform-complete-backup-$DATE.tar.gz" \
        gs://terraform-backups/
fi

# Cleanup old backups (keep last 30 days)
find "$BACKUP_DIR" -name "terraform-complete-backup-*.tar.gz" \
    -mtime +30 -delete

echo "🎉 All backups completed successfully"
EOF

chmod +x scripts/backup-terraform-state.sh
```

### Disaster Recovery Procedures

```bash
# Disaster recovery script
cat > scripts/disaster-recovery.sh <<'EOF'
#!/bin/bash

BACKUP_FILE="$1"
TARGET_ENVIRONMENT="$2"

if [[ -z "$BACKUP_FILE" || -z "$TARGET_ENVIRONMENT" ]]; then
    echo "Usage: $0 <backup-file.tar.gz> <target-environment>"
    echo "Example: $0 terraform-complete-backup-20240115_143000.tar.gz production"
    exit 1
fi

# Verify backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Create recovery directory
RECOVERY_DIR="/tmp/terraform-recovery-$(date +%s)"
mkdir -p "$RECOVERY_DIR"

# Extract backup
echo "📦 Extracting backup..."
tar -xzf "$BACKUP_FILE" -C "$RECOVERY_DIR"

# Navigate to target environment
cd "environments/$TARGET_ENVIRONMENT" || {
    echo "❌ Target environment directory not found: environments/$TARGET_ENVIRONMENT"
    exit 1
}

# Backup current state before recovery
echo "💾 Backing up current state..."
terraform state pull > "current-state-backup-$(date +%Y%m%d_%H%M%S).json"

# Import recovered state
RECOVERED_STATE="$RECOVERY_DIR/$TARGET_ENVIRONMENT/terraform-state-*.json"
if [[ -f $RECOVERED_STATE ]]; then
    echo "🔄 Restoring state from backup..."
    terraform state push "$RECOVERED_STATE"
else
    echo "❌ No state file found in backup for environment: $TARGET_ENVIRONMENT"
    exit 1
fi

# Verify state consistency
echo "🔍 Verifying state consistency..."
if terraform plan -detailed-exitcode; then
    echo "✅ State restored successfully - no drift detected"
elif [[ $? -eq 2 ]]; then
    echo "⚠️  State restored but drift detected - manual review required"
    terraform plan
else
    echo "❌ State restoration failed - check error messages above"
    exit 1
fi

# Cleanup
rm -rf "$RECOVERY_DIR"

echo "🎉 Disaster recovery completed for environment: $TARGET_ENVIRONMENT"
echo "💡 Please review the plan output and apply changes if necessary"
EOF

chmod +x scripts/disaster-recovery.sh
```

### State Migration and Refactoring

```bash
# State migration script for refactoring
cat > scripts/migrate-state.sh <<'EOF'
#!/bin/bash

# Function to safely move resources in state
move_resource() {
    local old_address="$1"
    local new_address="$2"
    
    echo "Moving $old_address to $new_address"
    
    # Check if source resource exists
    if terraform state show "$old_address" &>/dev/null; then
        terraform state mv "$old_address" "$new_address"
        echo "✅ Successfully moved $old_address to $new_address"
    else
        echo "⚠️  Resource not found: $old_address"
    fi
}

# Function to import existing resources
import_resource() {
    local resource_address="$1"
    local resource_id="$2"
    
    echo "Importing $resource_id as $resource_address"
    
    if terraform import "$resource_address" "$resource_id"; then
        echo "✅ Successfully imported $resource_id as $resource_address"
    else
        echo "❌ Failed to import $resource_id"
    fi
}

# Example migrations
echo "🔄 Starting state migrations..."

# Move resources to modules
move_resource "aws_instance.web" "module.web_servers.aws_instance.main[0]"
move_resource "aws_security_group.web" "module.web_servers.aws_security_group.main"

# Import existing resources
import_resource "aws_s3_bucket.existing_bucket" "existing-bucket-name"

# Remove resources that are no longer managed
terraform state rm aws_instance.deprecated

echo "🎉 State migrations completed"
echo "💡 Run 'terraform plan' to verify changes"
EOF

chmod +x scripts/migrate-state.sh
```

## 13. Troubleshooting

### Common Issues and Solutions

```bash
# Terraform troubleshooting script
cat > scripts/troubleshoot-terraform.sh <<'EOF'
#!/bin/bash

echo "🔧 Terraform Troubleshooting Tool"
echo "================================"

# Check Terraform installation
check_installation() {
    echo "📋 Checking Terraform installation..."
    
    if command -v terraform &> /dev/null; then
        terraform version
        echo "✅ Terraform is installed"
    else
        echo "❌ Terraform is not installed or not in PATH"
        return 1
    fi
}

# Check configuration syntax
check_configuration() {
    echo "📋 Checking configuration syntax..."
    
    if terraform fmt -check -diff; then
        echo "✅ Configuration is properly formatted"
    else
        echo "⚠️  Configuration formatting issues found"
        terraform fmt -diff
    fi
    
    if terraform validate; then
        echo "✅ Configuration is valid"
    else
        echo "❌ Configuration validation failed"
        return 1
    fi
}

# Check provider authentication
check_providers() {
    echo "📋 Checking provider authentication..."
    
    # AWS
    if aws sts get-caller-identity &>/dev/null; then
        echo "✅ AWS credentials are valid"
    else
        echo "⚠️  AWS credentials may be invalid or not configured"
    fi
    
    # Azure
    if az account show &>/dev/null; then
        echo "✅ Azure credentials are valid"
    else
        echo "⚠️  Azure credentials may be invalid or not configured"
    fi
    
    # GCP
    if gcloud auth list --filter=status:ACTIVE --format="value(account)" &>/dev/null; then
        echo "✅ GCP credentials are valid"
    else
        echo "⚠️  GCP credentials may be invalid or not configured"
    fi
}

# Check state file
check_state() {
    echo "📋 Checking state file..."
    
    if terraform state list &>/dev/null; then
        resource_count=$(terraform state list | wc -l)
        echo "✅ State file is accessible with $resource_count resources"
    else
        echo "❌ Cannot access state file"
        return 1
    fi
}

# Check for common issues
check_common_issues() {
    echo "📋 Checking for common issues..."
    
    # Check for lock file
    if [[ -f ".terraform.lock.hcl" ]]; then
        echo "✅ Lock file exists"
    else
        echo "⚠️  Lock file missing - run 'terraform init'"
    fi
    
    # Check for local state file in production
    if [[ -f "terraform.tfstate" ]] && [[ $(terraform workspace show) == "production" ]]; then
        echo "⚠️  Local state file detected in production workspace"
        echo "    Consider using remote state for production"
    fi
    
    # Check for hardcoded secrets
    if grep -r "password\s*=\s*\"" . --include="*.tf" --include="*.tfvars" 2>/dev/null; then
        echo "⚠️  Potential hardcoded passwords found"
    fi
    
    # Check for large state file
    if [[ -f "terraform.tfstate" ]]; then
        state_size=$(stat -f%z "terraform.tfstate" 2>/dev/null || stat -c%s "terraform.tfstate" 2>/dev/null)
        if [[ $state_size -gt 10485760 ]]; then  # 10MB
            echo "⚠️  Large state file detected ($(($state_size / 1024 / 1024))MB)"
            echo "    Consider splitting into smaller configurations"
        fi
    fi
}

# Debug mode information
debug_info() {
    echo "📋 Debug information..."
    
    echo "Working directory: $(pwd)"
    echo "Terraform workspace: $(terraform workspace show)"
    echo "Environment variables:"
    env | grep -E "^(TF_|AWS_|ARM_|GOOGLE_)" | sed 's/=.*/=***/' | sort
}

# Run all checks
run_all_checks() {
    check_installation || return 1
    check_configuration || return 1
    check_providers
    check_state || return 1
    check_common_issues
    debug_info
}

# Main execution
case "${1:-all}" in
    "installation")
        check_installation
        ;;
    "config")
        check_configuration
        ;;
    "providers")
        check_providers
        ;;
    "state")
        check_state
        ;;
    "common")
        check_common_issues
        ;;
    "debug")
        debug_info
        ;;
    "all")
        run_all_checks
        ;;
    *)
        echo "Usage: $0 [installation|config|providers|state|common|debug|all]"
        exit 1
        ;;
esac
EOF

chmod +x scripts/troubleshoot-terraform.sh
```

### Advanced Debugging

```bash
# Advanced debugging techniques
cat > scripts/debug-terraform.sh <<'EOF'
#!/bin/bash

# Enable debug logging
export TF_LOG=DEBUG
export TF_LOG_PATH="terraform-debug-$(date +%Y%m%d_%H%M%S).log"

# Create debug session
debug_session() {
    local operation="$1"
    shift
    
    echo "🐛 Starting debug session for: $operation"
    echo "Debug log: $TF_LOG_PATH"
    
    # Capture detailed timing information
    time terraform "$operation" "$@" 2>&1 | tee -a "$TF_LOG_PATH"
    
    local exit_code=${PIPESTATUS[0]}
    
    if [[ $exit_code -ne 0 ]]; then
        echo "❌ Operation failed with exit code: $exit_code"
        echo "📄 Last 50 lines of debug log:"
        tail -50 "$TF_LOG_PATH"
    else
        echo "✅ Operation completed successfully"
    fi
    
    return $exit_code
}

# Analyze state file for issues
analyze_state() {
    echo "🔍 Analyzing state file..."
    
    # Check for orphaned resources
    echo "Checking for potential orphaned resources..."
    terraform state list | while read resource; do
        if ! terraform plan -target="$resource" -detailed-exitcode >/dev/null 2>&1; then
            echo "⚠️  Potential issue with resource: $resource"
        fi
    done
    
    # Check for large resources in state
    echo "Checking for large resources..."
    terraform state pull | jq -r '.resources[] | select(.instances[0].attributes | length > 50) | .address' 2>/dev/null | head -10
}

# Provider debug information
debug_providers() {
    echo "🔍 Debugging provider issues..."
    
    # Show provider configuration
    terraform providers
    
    # Check provider cache
    if [[ -d "$HOME/.terraform.d/plugin-cache" ]]; then
        echo "Provider cache contents:"
        ls -la "$HOME/.terraform.d/plugin-cache"
    fi
    
    # Check for provider version conflicts
    terraform version -json | jq '.provider_selections' 2>/dev/null
}

# Network and API debugging
debug_network() {
    echo "🌐 Debugging network connectivity..."
    
    # Test connectivity to common endpoints
    local endpoints=(
        "https://releases.hashicorp.com"
        "https://registry.terraform.io"
        "https://api.github.com"
        "https://aws.amazon.com"
        "https://management.azure.com"
        "https://www.googleapis.com"
    )
    
    for endpoint in "${endpoints[@]}"; do
        if curl -s --connect-timeout 5 "$endpoint" >/dev/null; then
            echo "✅ $endpoint - OK"
        else
            echo "❌ $endpoint - FAILED"
        fi
    done
}

# Performance analysis
analyze_performance() {
    echo "📊 Analyzing Terraform performance..."
    
    # Generate and analyze dependency graph
    terraform graph > dependency-graph.dot
    
    # Count resources by type
    echo "Resource distribution:"
    terraform state list | cut -d. -f1 | sort | uniq -c | sort -nr | head -10
    
    # Estimate plan time based on resources
    resource_count=$(terraform state list | wc -l)
    estimated_time=$((resource_count * 2))  # Rough estimate: 2 seconds per resource
    echo "Estimated plan time: ${estimated_time} seconds for $resource_count resources"
}

# Usage
case "${1:-help}" in
    "session")
        shift
        debug_session "$@"
        ;;
    "state")
        analyze_state
        ;;
    "providers")
        debug_providers
        ;;
    "network")
        debug_network
        ;;
    "performance")
        analyze_performance
        ;;
    "all")
        debug_providers
        debug_network
        analyze_state
        analyze_performance
        ;;
    "help"|*)
        echo "Usage: $0 [session|state|providers|network|performance|all]"
        echo ""
        echo "  session <operation> [args]  - Debug specific Terraform operation"
        echo "  state                       - Analyze state file for issues"
        echo "  providers                   - Debug provider configuration"
        echo "  network                     - Test network connectivity"
        echo "  performance                 - Analyze performance characteristics"
        echo "  all                         - Run all debug checks"
        ;;
esac
EOF

chmod +x scripts/debug-terraform.sh
```

## 14. Maintenance

### Update Procedures

```bash
# Terraform update script
cat > scripts/update-terraform.sh <<'EOF'
#!/bin/bash

CURRENT_VERSION=$(terraform version -json | jq -r '.terraform_version')
echo "Current Terraform version: $CURRENT_VERSION"

# Check for latest version
check_latest_version() {
    local latest_version
    latest_version=$(curl -s https://api.github.com/repos/hashicorp/terraform/releases/latest | jq -r '.tag_name' | sed 's/v//')
    echo "Latest Terraform version: $latest_version"
    
    if [[ "$CURRENT_VERSION" != "$latest_version" ]]; then
        echo "⚠️  Update available: $CURRENT_VERSION → $latest_version"
        return 1
    else
        echo "✅ Terraform is up to date"
        return 0
    fi
}

# Update using package manager
update_terraform() {
    echo "🔄 Updating Terraform..."
    
    if command -v apt &>/dev/null; then
        sudo apt update && sudo apt upgrade terraform
    elif command -v yum &>/dev/null; then
        sudo yum update terraform
    elif command -v dnf &>/dev/null; then
        sudo dnf update terraform
    elif command -v pacman &>/dev/null; then
        sudo pacman -Syu terraform
    elif command -v zypper &>/dev/null; then
        sudo zypper update terraform
    elif command -v brew &>/dev/null; then
        brew upgrade terraform
    else
        echo "❌ No supported package manager found"
        echo "💡 Please update manually from: https://releases.hashicorp.com/terraform/"
        return 1
    fi
}

# Update providers
update_providers() {
    echo "🔄 Updating providers..."
    terraform init -upgrade
}

# Verify update
verify_update() {
    echo "🔍 Verifying update..."
    
    terraform version
    
    # Test basic functionality
    if terraform validate; then
        echo "✅ Update verification successful"
    else
        echo "❌ Update verification failed"
        return 1
    fi
}

# Main update process
main() {
    if check_latest_version; then
        exit 0
    fi
    
    echo "Proceed with update? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        update_terraform || exit 1
        update_providers || exit 1
        verify_update || exit 1
        echo "🎉 Terraform update completed successfully"
    else
        echo "Update cancelled"
    fi
}

main "$@"
EOF

chmod +x scripts/update-terraform.sh
```

### Maintenance Tasks

```bash
# Comprehensive maintenance script
cat > scripts/terraform-maintenance.sh <<'EOF'
#!/bin/bash

MAINTENANCE_LOG="/var/log/terraform-maintenance-$(date +%Y%m%d_%H%M%S).log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$MAINTENANCE_LOG"
}

# Cleanup old plan files
cleanup_plans() {
    log "🧹 Cleaning up old plan files..."
    find . -name "*.tfplan" -mtime +7 -delete
    find . -name "*.tfplan.json" -mtime +7 -delete
    log "✅ Plan file cleanup completed"
}

# Cleanup provider cache
cleanup_provider_cache() {
    log "🧹 Cleaning up provider cache..."
    if [[ -d "$HOME/.terraform.d/plugin-cache" ]]; then
        # Remove providers older than 30 days
        find "$HOME/.terraform.d/plugin-cache" -type f -mtime +30 -delete
        
        # Remove empty directories
        find "$HOME/.terraform.d/plugin-cache" -type d -empty -delete
        
        cache_size=$(du -sh "$HOME/.terraform.d/plugin-cache" 2>/dev/null | cut -f1)
        log "✅ Provider cache cleanup completed - current size: $cache_size"
    fi
}

# Validate all configurations
validate_configurations() {
    log "🔍 Validating all configurations..."
    
    local validation_failed=false
    
    # Find all directories with Terraform files
    find . -name "*.tf" -exec dirname {} \; | sort -u | while read -r dir; do
        log "Validating: $dir"
        cd "$dir" || continue
        
        if terraform validate; then
            log "✅ $dir validation passed"
        else
            log "❌ $dir validation failed"
            validation_failed=true
        fi
        
        cd - > /dev/null
    done
    
    if [[ "$validation_failed" == "true" ]]; then
        log "⚠️  Some validations failed - please review"
    else
        log "✅ All validations passed"
    fi
}

# Check for deprecated features
check_deprecated() {
    log "🔍 Checking for deprecated features..."
    
    # Check for deprecated syntax
    local deprecated_patterns=(
        "provider\s+\"[^\"]+\"\s+{" # Old provider syntax
        "terraform\s+{[^}]*version\s*=" # Old terraform version constraints
        "ignore_changes\s*=" # Old ignore_changes syntax
    )
    
    for pattern in "${deprecated_patterns[@]}"; do
        if grep -r "$pattern" . --include="*.tf" 2>/dev/null; then
            log "⚠️  Deprecated pattern found: $pattern"
        fi
    done
    
    log "✅ Deprecation check completed"
}

# Security audit
security_audit() {
    log "🔒 Performing security audit..."
    
    # Check for potential security issues
    local security_issues=()
    
    # Check for hardcoded secrets
    if grep -r -i "password\s*=\s*\"[^$]" . --include="*.tf" --include="*.tfvars" 2>/dev/null; then
        security_issues+=("Potential hardcoded passwords")
    fi
    
    # Check for public access
    if grep -r "0.0.0.0/0" . --include="*.tf" 2>/dev/null; then
        security_issues+=("Public access (0.0.0.0/0) found")
    fi
    
    # Check for unencrypted resources
    if grep -r "encrypt.*=.*false" . --include="*.tf" 2>/dev/null; then
        security_issues+=("Unencrypted resources found")
    fi
    
    if [[ ${#security_issues[@]} -gt 0 ]]; then
        log "⚠️  Security issues found:"
        for issue in "${security_issues[@]}"; do
            log "  - $issue"
        done
    else
        log "✅ No obvious security issues found"
    fi
}

# State health check
state_health_check() {
    log "🏥 Performing state health check..."
    
    # Check state file size
    if [[ -f "terraform.tfstate" ]]; then
        state_size=$(stat -f%z "terraform.tfstate" 2>/dev/null || stat -c%s "terraform.tfstate" 2>/dev/null)
        state_size_mb=$((state_size / 1024 / 1024))
        
        if [[ $state_size_mb -gt 50 ]]; then
            log "⚠️  Large state file detected: ${state_size_mb}MB"
        else
            log "✅ State file size OK: ${state_size_mb}MB"
        fi
    fi
    
    # Check for drift
    if terraform plan -detailed-exitcode > /dev/null 2>&1; then
        log "✅ No infrastructure drift detected"
    else
        exit_code=$?
        if [[ $exit_code -eq 2 ]]; then
            log "⚠️  Infrastructure drift detected"
        else
            log "❌ Error checking for drift"
        fi
    fi
}

# Generate maintenance report
generate_report() {
    log "📊 Generating maintenance report..."
    
    local report_file="/tmp/terraform-maintenance-report-$(date +%Y%m%d_%H%M%S).md"
    
    cat > "$report_file" <<EOF
# Terraform Maintenance Report

**Date:** $(date)
**Duration:** $((SECONDS / 60)) minutes

## Summary

- Configuration validation: $(grep "validation" "$MAINTENANCE_LOG" | grep -c "passed")
- Security audit: Completed
- State health check: Completed
- Cleanup operations: Completed

## Recommendations

$(grep "⚠️" "$MAINTENANCE_LOG" | sed 's/.*⚠️  /- /')

## Full Log

\`\`\`
$(cat "$MAINTENANCE_LOG")
\`\`\`
EOF
    
    log "📄 Maintenance report generated: $report_file"
    
    # Email report if configured
    if [[ -n "$MAINTENANCE_EMAIL" ]]; then
        mail -s "Terraform Maintenance Report - $(date)" "$MAINTENANCE_EMAIL" < "$report_file"
        log "📧 Report emailed to: $MAINTENANCE_EMAIL"
    fi
}

# Main maintenance routine
main() {
    log "🚀 Starting Terraform maintenance..."
    
    cleanup_plans
    cleanup_provider_cache
    validate_configurations
    check_deprecated
    security_audit
    state_health_check
    generate_report
    
    log "🎉 Terraform maintenance completed"
    log "📊 Total runtime: $((SECONDS / 60)) minutes"
}

# Run maintenance
main "$@"
EOF

chmod +x scripts/terraform-maintenance.sh

# Schedule maintenance with cron
cat > scripts/schedule-maintenance.sh <<'EOF'
#!/bin/bash

# Add to crontab for weekly maintenance
(crontab -l 2>/dev/null; echo "0 2 * * 0 /path/to/terraform-maintenance.sh") | crontab -

echo "✅ Weekly maintenance scheduled for Sundays at 2 AM"
EOF

chmod +x scripts/schedule-maintenance.sh
```

## 15. Integration Examples

### CI/CD Pipeline Integration

```bash
# GitHub Actions workflow
mkdir -p .github/workflows
cat > .github/workflows/terraform.yml <<EOF
name: Terraform Multi-Cloud Deployment

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  TF_VERSION: 1.6.4

jobs:
  terraform:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [development, staging, production]
        
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Setup Terraform
      uses: hashicorp/setup-terraform@v3
      with:
        terraform_version: \${{ env.TF_VERSION }}
        cli_config_credentials_token: \${{ secrets.TF_CLOUD_TOKEN }}
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v4
      with:
        aws-access-key-id: \${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: \${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-west-2
    
    - name: Terraform Format Check
      run: terraform fmt -check -recursive
    
    - name: Terraform Initialize
      run: terraform init
      working-directory: environments/\${{ matrix.environment }}
    
    - name: Terraform Validate
      run: terraform validate
      working-directory: environments/\${{ matrix.environment }}
    
    - name: Terraform Plan
      run: terraform plan -var-file="\${{ matrix.environment }}.tfvars"
      working-directory: environments/\${{ matrix.environment }}
    
    - name: Security Scan with Checkov
      uses: bridgecrewio/checkov-action@master
      with:
        directory: .
        framework: terraform
        output_format: sarif
        output_file_path: checkov.sarif
    
    - name: Upload Checkov results
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: checkov.sarif
    
    - name: Terraform Apply (Production)
      if: github.ref == 'refs/heads/main' && matrix.environment == 'production'
      run: terraform apply -auto-approve -var-file="production.tfvars"
      working-directory: environments/production
EOF
```

### GitLab CI Integration

```bash
cat > .gitlab-ci.yml <<EOF
stages:
  - validate
  - plan
  - apply
  - destroy

variables:
  TF_ROOT: \${CI_PROJECT_DIR}
  TF_VERSION: "1.6.4"
  TF_IN_AUTOMATION: "true"

cache:
  key: "\${TF_ROOT}"
  paths:
    - \${TF_ROOT}/.terraform

before_script:
  - cd \${TF_ROOT}
  - terraform version
  - terraform init

validate:
  stage: validate
  script:
    - terraform fmt -check -recursive
    - terraform validate
    - |
      for dir in environments/*/; do
        cd "\$dir"
        terraform validate
        cd -
      done
  rules:
    - if: '\$CI_MERGE_REQUEST_IID'
    - if: '\$CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH'

plan:production:
  stage: plan
  script:
    - cd environments/production
    - terraform plan -var-file="production.tfvars" -out="production.tfplan"
  artifacts:
    paths:
      - environments/production/production.tfplan
    expire_in: 1 week
  rules:
    - if: '\$CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH'

apply:production:
  stage: apply
  script:
    - cd environments/production
    - terraform apply -input=false "production.tfplan"
  dependencies:
    - plan:production
  rules:
    - if: '\$CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH'
      when: manual
EOF
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        TF_VERSION = '1.6.4'
        AWS_DEFAULT_REGION = 'us-west-2'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh '''
                    # Install Terraform if not present
                    if ! command -v terraform &> /dev/null; then
                        wget https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip
                        unzip terraform_${TF_VERSION}_linux_amd64.zip
                        chmod +x terraform
                        sudo mv terraform /usr/local/bin/
                    fi
                    
                    terraform version
                '''
            }
        }
        
        stage('Validate') {
            parallel {
                stage('Format Check') {
                    steps {
                        sh 'terraform fmt -check -recursive'
                    }
                }
                stage('Configuration Validation') {
                    steps {
                        sh '''
                            for dir in environments/*/; do
                                cd "$dir"
                                terraform init
                                terraform validate
                                cd -
                            done
                        '''
                    }
                }
                stage('Security Scan') {
                    steps {
                        sh '''
                            # Install and run Checkov
                            pip3 install checkov
                            checkov --framework terraform --directory .
                        '''
                    }
                }
            }
        }
        
        stage('Plan') {
            steps {
                script {
                    def environments = ['development', 'staging', 'production']
                    def planResults = [:]
                    
                    environments.each { env ->
                        planResults[env] = {
                            dir("environments/${env}") {
                                sh """
                                    terraform init
                                    terraform plan -var-file="${env}.tfvars" -out="${env}.tfplan"
                                """
                            }
                        }
                    }
                    
                    parallel planResults
                }
            }
        }
        
        stage('Apply') {
            when {
                branch 'main'
            }
            steps {
                script {
                    input message: 'Apply Terraform changes?', ok: 'Apply'
                    
                    dir('environments/production') {
                        sh 'terraform apply -input=false production.tfplan'
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'environments/**/*.tfplan', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'checkov-report',
                reportFiles: 'index.html',
                reportName: 'Checkov Security Report'
            ])
        }
        failure {
            emailext (
                subject: "Terraform Pipeline Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "The Terraform pipeline has failed. Please check the build logs for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
```

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
    - main
    - develop
  paths:
    include:
    - terraform/*
    - environments/*

pool:
  vmImage: 'ubuntu-latest'

variables:
  TF_VERSION: '1.6.4'
  TF_IN_AUTOMATION: 'true'

stages:
- stage: Validate
  displayName: 'Validate Terraform'
  jobs:
  - job: ValidateJob
    displayName: 'Validate Configuration'
    steps:
    - task: TerraformInstaller@0
      displayName: 'Install Terraform'
      inputs:
        terraformVersion: $(TF_VERSION)
    
    - script: |
        terraform fmt -check -recursive
        if [ $? -ne 0 ]; then
          echo "##vso[task.logissue type=error]Terraform files are not formatted correctly"
          exit 1
        fi
      displayName: 'Check Terraform Format'
    
    - script: |
        for dir in environments/*/; do
          echo "Validating $dir"
          cd "$dir"
          terraform init -backend=false
          terraform validate
          cd -
        done
      displayName: 'Validate All Environments'
    
    - script: |
        # Install and run security scanning
        pip install checkov
        checkov --framework terraform --directory . --output cli --output junitxml --output-file-path checkov-results.xml
      displayName: 'Security Scan with Checkov'
    
    - task: PublishTestResults@2
      condition: always()
      inputs:
        testResultsFormat: 'JUnit'
        testResultsFiles: 'checkov-results.xml'
        failTaskOnFailedTests: true

- stage: Plan
  displayName: 'Terraform Plan'
  dependsOn: Validate
  condition: succeeded()
  jobs:
  - job: PlanProduction
    displayName: 'Plan Production Environment'
    steps:
    - task: TerraformInstaller@0
      inputs:
        terraformVersion: $(TF_VERSION)
    
    - task: AzureCLI@2
      displayName: 'Configure Azure Backend'
      inputs:
        azureSubscription: 'Production-ServiceConnection'
        scriptType: 'bash'
        scriptLocation: 'inlineScript'
        inlineScript: |
          cd environments/production
          terraform init \
            -backend-config="resource_group_name=$(BACKEND_RESOURCE_GROUP)" \
            -backend-config="storage_account_name=$(BACKEND_STORAGE_ACCOUNT)" \
            -backend-config="container_name=$(BACKEND_CONTAINER)" \
            -backend-config="key=production.tfstate"
    
    - task: AzureCLI@2
      displayName: 'Terraform Plan'
      inputs:
        azureSubscription: 'Production-ServiceConnection'
        scriptType: 'bash'
        scriptLocation: 'inlineScript'
        inlineScript: |
          cd environments/production
          terraform plan -var-file="production.tfvars" -out=production.tfplan
    
    - task: PublishPipelineArtifact@1
      inputs:
        targetPath: 'environments/production/production.tfplan'
        artifact: 'terraform-plan-production'

- stage: Apply
  displayName: 'Terraform Apply'
  dependsOn: Plan
  condition: and(succeeded(), eq(variables['Build.SourceBranch'], 'refs/heads/main'))
  jobs:
  - deployment: ApplyProduction
    displayName: 'Apply to Production'
    environment: 'Production'
    strategy:
      runOnce:
        deploy:
          steps:
          - task: TerraformInstaller@0
            inputs:
              terraformVersion: $(TF_VERSION)
          
          - task: DownloadPipelineArtifact@2
            inputs:
              artifact: 'terraform-plan-production'
              path: $(System.DefaultWorkingDirectory)/environments/production
          
          - task: AzureCLI@2
            displayName: 'Terraform Apply'
            inputs:
              azureSubscription: 'Production-ServiceConnection'
              scriptType: 'bash'
              scriptLocation: 'inlineScript'
              inlineScript: |
                cd environments/production
                terraform init \
                  -backend-config="resource_group_name=$(BACKEND_RESOURCE_GROUP)" \
                  -backend-config="storage_account_name=$(BACKEND_STORAGE_ACCOUNT)" \
                  -backend-config="container_name=$(BACKEND_CONTAINER)" \
                  -backend-config="key=production.tfstate"
                terraform apply -input=false production.tfplan
```

### Advanced Atlantis Configuration

```yaml
# atlantis.yaml - GitOps for Terraform
version: 3
automerge: false
delete_source_branch_on_merge: true

projects:
- name: production
  dir: environments/production
  workspace: production
  terraform_version: v1.6.4
  apply_requirements: [approved, mergeable]
  plan_requirements: [mergeable]
  workflow: production
  
- name: staging
  dir: environments/staging  
  workspace: staging
  terraform_version: v1.6.4
  apply_requirements: [mergeable]
  workflow: staging

- name: development
  dir: environments/development
  workspace: development
  terraform_version: v1.6.4
  workflow: development

workflows:
  production:
    plan:
      steps:
      - env:
          name: TF_IN_AUTOMATION
          value: "true"
      - init
      - plan:
          extra_args: ["-var-file=production.tfvars"]
      - run: |
          # Security scanning
          checkov --framework terraform --directory . --check CKV_AWS_79,CKV_AWS_8
          
          # Cost estimation
          if command -v infracost &> /dev/null; then
            infracost breakdown --path=.
          fi
    apply:
      steps:
      - env:
          name: TF_IN_AUTOMATION  
          value: "true"
      - init
      - apply:
          extra_args: ["-var-file=production.tfvars"]
      - run: |
          # Post-apply notifications
          curl -X POST -H 'Content-type: application/json' \
            --data '{"text":"✅ Production infrastructure updated successfully"}' \
            "$SLACK_WEBHOOK_URL"
            
  staging:
    plan:
      steps:
      - init
      - plan:
          extra_args: ["-var-file=staging.tfvars"]
    apply:
      steps:
      - init  
      - apply:
          extra_args: ["-var-file=staging.tfvars"]
          
  development:
    plan:
      steps:
      - init
      - plan:
          extra_args: ["-var-file=development.tfvars"]
    apply:
      steps:
      - init
      - apply:
          extra_args: ["-var-file=development.tfvars"]
```

### Kubernetes Operator Integration

```yaml
# terraform-operator.yaml - Deploy Terraform via Kubernetes
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: terraforms.infrastructure.company.com
spec:
  group: infrastructure.company.com
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              source:
                type: object
                properties:
                  git:
                    type: object
                    properties:
                      url:
                        type: string
                      branch:
                        type: string
                      path:
                        type: string
              variables:
                type: object
                additionalProperties:
                  type: string
              workspace:
                type: string
              destroy:
                type: boolean
                default: false
          status:
            type: object
            properties:
              phase:
                type: string
              lastApplied:
                type: string
                format: date-time
              outputs:
                type: object
                additionalProperties:
                  type: string
  scope: Namespaced
  names:
    plural: terraforms
    singular: terraform
    kind: Terraform
    shortNames:
    - tf

---
# Example Terraform resource managed by Kubernetes
apiVersion: infrastructure.company.com/v1
kind: Terraform
metadata:
  name: web-application-infrastructure
  namespace: production
spec:
  source:
    git:
      url: "https://github.com/company/infrastructure"
      branch: "main"
      path: "environments/production"
  workspace: "production"
  variables:
    project_name: "web-application"
    environment: "production"
    instance_type: "m5.large"
    min_capacity: "3"
    max_capacity: "10"
  destroy: false
```

### Terraform with Vault Integration

```bash
# Vault integration for dynamic credentials
cat > vault-integration.tf <<EOF
# Vault provider for dynamic secrets
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.20"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "vault" {
  address = var.vault_address
  # Authentication handled via VAULT_TOKEN env var or AWS auth
}

# Dynamic AWS credentials from Vault
data "vault_aws_access_credentials" "aws_creds" {
  backend = "aws"
  role    = "terraform-${terraform.workspace}"
  type    = "creds"
}

provider "aws" {
  region     = var.aws_region
  access_key = data.vault_aws_access_credentials.aws_creds.access_key
  secret_key = data.vault_aws_access_credentials.aws_creds.secret_key
  token      = data.vault_aws_access_credentials.aws_creds.security_token
}

# Dynamic database credentials
data "vault_database_credentials" "db" {
  backend = "database"
  role    = "terraform-${terraform.workspace}-db"
}

# RDS instance with dynamic credentials
resource "aws_db_instance" "main" {
  identifier = "${var.project_name}-${terraform.workspace}"
  
  engine         = "postgresql"
  engine_version = "15.4"
  instance_class = var.db_instance_class
  
  allocated_storage = 20
  storage_encrypted = true
  
  db_name  = var.database_name
  username = data.vault_database_credentials.db.username
  password = data.vault_database_credentials.db.password
  
  skip_final_snapshot = false
  final_snapshot_identifier = "${var.project_name}-${terraform.workspace}-final"
  
  tags = local.common_tags
}

# Store outputs back in Vault
resource "vault_kv_secret_v2" "terraform_outputs" {
  mount = "terraform"
  name  = "${terraform.workspace}/outputs"
  
  data_json = jsonencode({
    vpc_id           = aws_vpc.main.id
    database_endpoint = aws_db_instance.main.endpoint
    load_balancer_dns = aws_lb.main.dns_name
    timestamp        = timestamp()
  })
}
EOF

# Vault configuration script
cat > scripts/setup-vault-integration.sh <<'EOF'
#!/bin/bash

VAULT_ADDR="${VAULT_ADDR:-https://vault.company.com}"
VAULT_TOKEN="${VAULT_TOKEN}"

# Enable AWS secrets engine
vault auth -method=aws
vault secrets enable -path=aws aws

# Configure AWS secrets engine
vault write aws/config/root \
    access_key="$AWS_ACCESS_KEY_ID" \
    secret_key="$AWS_SECRET_ACCESS_KEY" \
    region="us-west-2"

# Create Terraform role for each environment
for env in development staging production; do
    vault write aws/roles/terraform-$env \
        credential_type="assumed_role" \
        role_arns="arn:aws:iam::ACCOUNT:role/TerraformRole-$env" \
        default_sts_ttl="3600" \
        max_sts_ttl="7200"
done

# Enable database secrets engine
vault secrets enable database

# Configure PostgreSQL database
vault write database/config/production-db \
    plugin_name="postgresql-database-plugin" \
    connection_url="postgresql://{{username}}:{{password}}@postgres.company.com:5432/terraform?sslmode=require" \
    allowed_roles="terraform-production-db" \
    username="vault-admin" \
    password="vault-admin-password"

# Create database role
vault write database/roles/terraform-production-db \
    db_name="production-db" \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

echo "✅ Vault integration configured successfully"
EOF

chmod +x scripts/setup-vault-integration.sh
```

## 16. Additional Resources

- [Official Terraform Documentation](https://developer.hashicorp.com/terraform/docs)
- [Terraform Registry](https://registry.terraform.io/)
- [Terraform Best Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices)
- [Multi-Cloud Architecture Guide](https://developer.hashicorp.com/terraform/tutorials/aws-get-started)
- [Security Best Practices](https://developer.hashicorp.com/terraform/language/values/sensitive)
- [AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Azure Provider Documentation](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs)
- [GCP Provider Documentation](https://registry.terraform.io/providers/hashicorp/google/latest/docs)
- [Terraform Community Forum](https://discuss.hashicorp.com/c/terraform-core)
- [HashiCorp Learn Terraform](https://learn.hashicorp.com/terraform)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.