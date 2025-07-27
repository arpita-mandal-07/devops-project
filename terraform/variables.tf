variable "aws_region" {
  default = "us-east-1"
}

variable "project_name" {
  default = "dvscops"
}

variable "github_token" {
  description = "GitHub token"
  type        = string
  default = "gp_token"
}

variable "github_owner" {
  description = "GitHub username"
  type        = string
  default = "gp-ops"
}

variable "github_repo" {
  description = "GitHub repo name"
  type        = string
  default = "project"
}

variable "github_branch" {
  default = "main"
}

variable "bucket_name" {
  description = "Artifact bucket name"
  type        = string
  default     = "dvscops-artifact-bucket"
}

variable "ami_id" {
  default = "ami-083e865b97bdf1c1b" # Amazon Linux 2023
}

variable "instance_type" {
  default = "t3.micro"
}

variable "key_name" {
  description = "EC2 key pair name"
  type        = string
  default     = "my-key-pair"
}

variable "instance_tag_key" {
  default = "Name"
}

variable "instance_tag_value" {
  default = "webserver"
}
