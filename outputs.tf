################################################################################
# VPC Outputs
################################################################################

output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "database_subnets" {
  description = "List of IDs of database subnets"
  value       = module.vpc.database_subnets
}

################################################################################
# RDS Outputs
################################################################################

output "rds_endpoint" {
  description = "RDS instance endpoint (with port)"
  value       = module.rds.db_instance_endpoint
  sensitive   = true
}

output "rds_address" {
  description = "RDS instance address (hostname only)"
  value       = module.rds.db_instance_address
  sensitive   = true
}

output "rds_port" {
  description = "RDS instance port"
  value       = module.rds.db_instance_port
}

output "rds_database_name" {
  description = "RDS database name"
  value       = module.rds.db_instance_name
}

output "rds_username" {
  description = "RDS database username"
  value       = module.rds.db_instance_username
  sensitive   = true
}

output "rds_password_secret_arn" {
  description = "ARN of the secret containing the RDS password"
  value       = module.rds.db_instance_master_user_secret_arn
  sensitive   = true
}

################################################################################
# ECR Outputs
################################################################################

output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}

output "ecr_repository_arn" {
  description = "ARN of the ECR repository"
  value       = aws_ecr_repository.app.arn
}

################################################################################
# ECS Outputs
################################################################################

output "ecs_cluster_id" {
  description = "ID of the ECS cluster"
  value       = module.ecs_cluster.id
}

output "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  value       = module.ecs_cluster.arn
}

output "ecs_task_definition_arn" {
  description = "ARN of the ECS task definition"
  value       = aws_ecs_task_definition.app.arn
}

output "ecs_task_definition_family" {
  description = "Family of the ECS task definition"
  value       = aws_ecs_task_definition.app.family
}

output "ecs_execution_role_arn" {
  description = "ARN of the ECS execution role"
  value       = aws_iam_role.ecs_execution_role.arn
}

output "ecs_task_role_arn" {
  description = "ARN of the ECS task role"
  value       = aws_iam_role.ecs_task_role.arn
}

output "ecs_autoscaling_target_resource_id" {
  description = "Resource ID of the ECS autoscaling target"
  value       = aws_appautoscaling_target.ecs_target.resource_id
}

output "ecs_autoscaling_min_capacity" {
  description = "Minimum capacity for ECS autoscaling"
  value       = aws_appautoscaling_target.ecs_target.min_capacity
}

output "ecs_autoscaling_max_capacity" {
  description = "Maximum capacity for ECS autoscaling"
  value       = aws_appautoscaling_target.ecs_target.max_capacity
}

################################################################################
# ALB Outputs
################################################################################

output "alb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the load balancer"
  value       = aws_lb.main.zone_id
}

output "alb_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.main.arn
}

output "alb_target_group_arn" {
  description = "ARN of the ECS target group"
  value       = aws_lb_target_group.ecs.arn
}

################################################################################
# S3 and CloudFront Outputs
################################################################################

output "s3_bucket_name" {
  description = "Name of the S3 bucket for frontend"
  value       = aws_s3_bucket.frontend.id
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket for frontend"
  value       = aws_s3_bucket.frontend.arn
}

output "s3_bucket_website_endpoint" {
  description = "Website endpoint of the S3 bucket"
  value       = aws_s3_bucket_website_configuration.frontend.website_endpoint
}

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.id
}

output "cloudfront_distribution_arn" {
  description = "ARN of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.arn
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.frontend.domain_name
}

output "cache_invalidation_role_arn" {
  description = "ARN of the CloudFront cache invalidation role (for CI/CD use)"
  value       = aws_iam_role.cloudfront_invalidation.arn
}

output "cache_invalidation_lambda_function_name" {
  description = "Name of the Lambda function for cache invalidation"
  value       = aws_lambda_function.cache_invalidation.function_name
}

################################################################################
# Security Group Outputs
################################################################################

output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "ecs_security_group_id" {
  description = "ID of the ECS security group"
  value       = aws_security_group.ecs_tasks.id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = aws_security_group.rds.id
}

################################################################################
# VPC Endpoints Outputs
################################################################################

output "vpc_endpoint_secretsmanager_id" {
  description = "ID of the Secrets Manager VPC endpoint"
  value       = aws_vpc_endpoint.secretsmanager.id
}

output "vpc_endpoint_s3_id" {
  description = "ID of the S3 VPC endpoint"
  value       = aws_vpc_endpoint.s3.id
}

output "vpc_endpoints_security_group_id" {
  description = "ID of the VPC endpoints security group"
  value       = aws_security_group.vpc_endpoints.id
}

################################################################################
# WAF Outputs
################################################################################

output "waf_cloudfront_web_acl_id" {
  description = "ID of the CloudFront WAF Web ACL"
  value       = aws_wafv2_web_acl.cloudfront.id
}

output "waf_cloudfront_web_acl_arn" {
  description = "ARN of the CloudFront WAF Web ACL"
  value       = aws_wafv2_web_acl.cloudfront.arn
}

output "waf_alb_web_acl_id" {
  description = "ID of the ALB WAF Web ACL"
  value       = aws_wafv2_web_acl.alb.id
}

output "waf_alb_web_acl_arn" {
  description = "ARN of the ALB WAF Web ACL"
  value       = aws_wafv2_web_acl.alb.arn
}

################################################################################
# Logging and Monitoring Outputs
################################################################################

output "cloudwatch_log_groups" {
  description = "CloudWatch log group names and ARNs"
  value = {
    ecs = {
      name = aws_cloudwatch_log_group.ecs.name
      arn  = aws_cloudwatch_log_group.ecs.arn
    }
    application = {
      name = aws_cloudwatch_log_group.application.name
      arn  = aws_cloudwatch_log_group.application.arn
    }
    lambda = {
      name = aws_cloudwatch_log_group.lambda.name
      arn  = aws_cloudwatch_log_group.lambda.arn
    }
    rds = {
      name = aws_cloudwatch_log_group.rds.name
      arn  = aws_cloudwatch_log_group.rds.arn
    }
    alb = {
      name = aws_cloudwatch_log_group.alb.name
      arn  = aws_cloudwatch_log_group.alb.arn
    }
  }
}

output "cloudwatch_dashboards" {
  description = "CloudWatch dashboard URLs"
  value = {
    main = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
    xray = "https://console.aws.amazon.com/cloudwatch/home?region=${var.aws_region}#dashboards:name=${aws_cloudwatch_dashboard.xray.dashboard_name}"
  }
}

output "xray_configuration" {
  description = "X-Ray configuration details"
  value = {
    sampling_rule_name = aws_xray_sampling_rule.default.rule_name
    encryption_key_arn = aws_kms_key.xray.arn
    service_map_url    = "https://console.aws.amazon.com/xray/home?region=${var.aws_region}#/service-map"
  }
}

output "cloudwatch_alarms" {
  description = "CloudWatch alarm names and ARNs"
  value = {
    ecs_high_cpu = {
      name = aws_cloudwatch_metric_alarm.ecs_high_cpu.alarm_name
      arn  = aws_cloudwatch_metric_alarm.ecs_high_cpu.arn
    }
    ecs_high_memory = {
      name = aws_cloudwatch_metric_alarm.ecs_high_memory.alarm_name
      arn  = aws_cloudwatch_metric_alarm.ecs_high_memory.arn
    }
    alb_high_response_time = {
      name = aws_cloudwatch_metric_alarm.alb_high_response_time.alarm_name
      arn  = aws_cloudwatch_metric_alarm.alb_high_response_time.arn
    }
    alb_high_error_rate = {
      name = aws_cloudwatch_metric_alarm.alb_high_error_rate.alarm_name
      arn  = aws_cloudwatch_metric_alarm.alb_high_error_rate.arn
    }
    rds_high_cpu = {
      name = aws_cloudwatch_metric_alarm.rds_high_cpu.alarm_name
      arn  = aws_cloudwatch_metric_alarm.rds_high_cpu.arn
    }
  }
}

output "alerts_sns_topic" {
  description = "SNS topic for monitoring alerts"
  value = {
    name = aws_sns_topic.alerts.name
    arn  = aws_sns_topic.alerts.arn
  }
}

output "kms_keys" {
  description = "KMS keys for encryption"
  value = {
    cloudwatch_logs = {
      arn   = aws_kms_key.cloudwatch_logs.arn
      alias = aws_kms_alias.cloudwatch_logs.name
    }
    xray = {
      arn   = aws_kms_key.xray.arn
      alias = aws_kms_alias.xray.name
    }
  }
}
