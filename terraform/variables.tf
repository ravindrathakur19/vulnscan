variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1" # Mumbai
}

variable "project_name" {
  description = "Used to name/tag all resources"
  type        = string
  default     = "vulnscan-pro"
}

variable "instance_type" {
  description = "EC2 instance type. t3.micro is Free-Tier eligible and enough for a single-replica K3s demo."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_size_gb" {
  description = "EBS root volume size in GB"
  type        = number
  default     = 20
}

variable "ssh_cidr" {
  description = <<-EOT
    CIDR allowed to reach port 22. Do NOT leave this as 0.0.0.0/0 for anything
    beyond a short-lived demo - set it to your own IP, e.g. "203.0.113.4/32"
    (find yours with: curl -s ifconfig.me).
  EOT
  type        = string
}

variable "key_pair_name" {
  description = "Name of an EXISTING EC2 key pair (create it in the AWS Console or with `aws ec2 create-key-pair` first). Terraform does not generate or store your private key."
  type        = string
}

variable "allowed_http_cidr" {
  description = "CIDR allowed to reach ports 80/443. 0.0.0.0/0 is normal for a public demo site."
  type        = string
  default     = "0.0.0.0/0"
}
