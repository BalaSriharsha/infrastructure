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

variable "backend_domain" {
  description = "Custom domain for the backend API (optional)"
  type        = string
  default     = null
}

variable "ecs_autoscaling_min_capacity" {
  description = "Minimum number of ECS tasks"
  type        = number
  default     = 1
  
  validation {
    condition     = var.ecs_autoscaling_min_capacity >= 1 && var.ecs_autoscaling_min_capacity <= 10
    error_message = "ECS autoscaling minimum capacity must be between 1 and 10."
  }
}

variable "ecs_autoscaling_max_capacity" {
  description = "Maximum number of ECS tasks"
  type        = number
  default     = 5
  
  validation {
    condition     = var.ecs_autoscaling_max_capacity >= 1 && var.ecs_autoscaling_max_capacity <= 20
    error_message = "ECS autoscaling maximum capacity must be between 1 and 20."
  }
}

variable "ecs_cpu_target_value" {
  description = "Target CPU utilization percentage for autoscaling"
  type        = number
  default     = 70
  
  validation {
    condition     = var.ecs_cpu_target_value >= 10 && var.ecs_cpu_target_value <= 90
    error_message = "ECS CPU target value must be between 10 and 90."
  }
}

variable "ecs_memory_target_value" {
  description = "Target memory utilization percentage for autoscaling"
  type        = number
  default     = 80
  
  validation {
    condition     = var.ecs_memory_target_value >= 10 && var.ecs_memory_target_value <= 90
    error_message = "ECS memory target value must be between 10 and 90."
  }
}
