#------------------------------------------------------------------------------
# REQUIRED
#------------------------------------------------------------------------------
variable "node_ips" {
  description = ""
  type        = list(string)
}

#------------------------------------------------------------------------------
# OPTIONAL
#------------------------------------------------------------------------------
variable "distro" {
  description = "Specify linux or darwin. Platform where RanchHand binary will be executed."
  default     = "linux"
}

variable "release" {
  description = "Specify the RanchHand release version to use. Check https://github.com/dominodatalab/ranchhand/releases for a list of available releases."
  default     = "latest"
}

variable "working_dir" {
  description = "Directory where ranchhand should be executed. Defaults to the current working directory."
  default     = ""
}

variable "cert_dnsnames" {
  description = "Hostnames for the rancher and rke ssl certs (comma-delimited)"
  default     = ["domino.rancher"]
}

variable "cert_ipaddresses" {
  description = "IP addresses for the rancher and rke ssl certs (comma-delimited)"
  default     = []
}

variable "ssh_username" {
  description = "SSH username on the nodes"
  default     = "admin"
}

variable "ssh_key_path" {
  description = "Path to the SSH private key that will be used to connect to the VMs"
  default     = "~/.ssh/id_rsa"
}

variable "ssh_proxy_user" {
  description = "Bastion host SSH username"
  default     = ""
}

variable "ssh_proxy_host" {
  description = "Bastion host used to proxy SSH connections"
  default     = ""
}

variable "admin_password" {
  description = "Password override for the initial admin user"
  default     = ""
}

