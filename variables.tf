variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.environment))
    error_message = "Environment must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "db_name" {
  description = "Database name"
  type        = string
  default     = "mediamint"
  
  validation {
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9]*$", var.db_name))
    error_message = "Database name must start with a letter and contain only alphanumeric characters."
  }
}

variable "db_username" {
  description = "Database username"
  type        = string
  default     = "admin"
  
  validation {
    condition     = length(var.db_username) >= 1 && length(var.db_username) <= 63
    error_message = "Database username must be between 1 and 63 characters."
  }
}

variable "frontend_domain" {
  description = "Custom domain for the frontend (optional)"
  type        = string
  default     = null
}

variable "acm_certificate_arn" {
  description = "ARN of the ACM certificate for the frontend domain (required if frontend_domain is set)"
  type        = string
  default     = null
}
