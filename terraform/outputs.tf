output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.vulnscan.id
}

output "public_ip" {
  description = "Public IP of the instance - the K3s node and app will be reachable here"
  value       = aws_instance.vulnscan.public_ip
}

output "public_dns" {
  description = "Public DNS name of the instance"
  value       = aws_instance.vulnscan.public_dns
}

output "security_group_id" {
  value = aws_security_group.vulnscan.id
}

output "ssh_command" {
  description = "Connect to the instance (replace the key path with your own .pem)"
  value       = "ssh -i /path/to/${var.key_pair_name}.pem ubuntu@${aws_instance.vulnscan.public_ip}"
}
