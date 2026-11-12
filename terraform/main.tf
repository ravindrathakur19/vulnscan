terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Local state by default for this academic/single-developer project.
  # For team use, uncomment and point this at an S3 bucket + DynamoDB lock table:
  # backend "s3" {
  #   bucket         = "your-tfstate-bucket"
  #   key            = "vulnscan-pro/terraform.tfstate"
  #   region         = "ap-south-1"
  #   dynamodb_table = "terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.aws_region
}

# Ubuntu Server 22.04 LTS, resolved dynamically (no hardcoded, region-specific AMI ID)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "vulnscan" {
  name        = "${var.project_name}-sg"
  description = "VulnScan Pro: SSH (restricted), HTTP/HTTPS public. No management ports exposed."
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH - restrict this to your own IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.ssh_cidr]
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_http_cidr]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.allowed_http_cidr]
  }

  # Grafana, Prometheus, Node Exporter, Alertmanager and the K3s API (6443) are
  # intentionally NOT opened here - monitoring stays on the cluster's private
  # network. Reach Grafana via `kubectl port-forward` or an SSH tunnel instead
  # of exposing :3000/:9090/:9100/:9093 to the internet. See README "Monitoring".

  egress {
    description = "Allow all outbound (needed to pull Docker images, apt/pip packages, etc.)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-sg"
    Project = var.project_name
  }
}

resource "aws_instance" "vulnscan" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_pair_name
  vpc_security_group_ids = [aws_security_group.vulnscan.id]

  root_block_device {
    volume_size           = var.root_volume_size_gb
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  # Installs Docker + K3s only; it does NOT build or deploy the app - that is
  # Jenkins's job. Keeping provisioning and deployment separate means
  # `terraform apply` never needs DockerHub credentials or app secrets.
  user_data = <<-EOF2
    #!/bin/bash
    set -e
    apt-get update -y
    apt-get install -y curl
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker ubuntu
    curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
  EOF2

  tags = {
    Name    = "${var.project_name}-ec2"
    Project = var.project_name
  }
}
