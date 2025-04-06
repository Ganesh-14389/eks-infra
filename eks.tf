################################################################################
#LOCALS FOR BREx MT EKS CLUSTER
################################################################################
locals {
  ami_id_brex_mt_eks_ng                   = "ami-04554dc3ea03dcb2a"
}

################################################################################
# BREx MT EKS VPC CNI IAM ROLE FOR SERVICE ACCOUNT
################################################################################
module "vpc_cni_irsa_01" {
  source  = "./modules/iam/sub-module/role-eks"
  role_name             = "eks-vpc-cni-irsa-01"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv4   = true
  oidc_providers = {
    main = {
      provider_arn               = module.cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }
  
}
################################################################################
# BREx MT EKS EBS CSI DRIVER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "ebs_csi_driver_kms_policy_01" {
  name        = "eks-ebs-csi-driver-kms-policy-01"
  description = "This Policy is for ebs csi driver irsa kms permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  
}
module "ebs_csi_driver_irsa_01" {
  source  = "./modules/iam/sub-module/role-eks"
  role_name = "eks-ebs-csi-driver-irsa-01"
  attach_ebs_csi_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
  
  role_policy_arns = {
    additional           = aws_iam_policy.ebs_csi_driver_kms_policy_01.arn
  }
  
}

# ################################################################################
# # BREx MT EKS EFS CSI DRIVER
# ################################################################################
resource "aws_iam_policy" "efs_csi_driver_kms_policy_01" {
  name        = "eks-efs-csi-driver-kms-policy-01"
  description = "This Policy is for efs csi driver irsa kms permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  
}

resource "aws_iam_policy" "efs_csi_driver_additional_policy_01" {
  name        = "eks-efs-csi-driver-additional-policy-01"
  description = "This Policy is for efs csi driver irsa additional permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "elasticfilesystem:TagResource" ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
  
}


module "efs_csi_driver_irsa_01" {
  source  = "./modules/iam/sub-module/role-eks"
  role_name = "eks-efs-csi-driver-irsa-01"
  attach_efs_csi_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.cluster_01.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
  
  role_policy_arns = {
    additional           = aws_iam_policy.efs_csi_driver_kms_policy_01.arn
    additional_efs_policy= aws_iam_policy.efs_csi_driver_additional_policy_01.arn
  }
  
}

################################################################################
# BREx MT EKS LOADBALANCER CONTROLLER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "load_balancer_controller_elb_policy_01" {
  name        = "eks-loadbalancer-controller-elb-policy-01"
  description = "This Policy is for loadbalancer controller irsa elb permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "elasticloadbalancing:AddTags" ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
  
}

module "load_balancer_controller_irsa_01" {
  source  = "./modules/iam/sub-module/role-eks"
  role_name = "eks-load-balancer-controller-irsa-01"
  attach_load_balancer_controller_policy = true
  oidc_providers = {
    ex = {
      provider_arn               = "${module.cluster_01.oidc_provider_arn}"
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }

  role_policy_arns = {
    additional           = aws_iam_policy.load_balancer_controller_elb_policy_01.arn
  }

  
}

################################################################################
# BREx MT EKS CUSTER AUTOSCALER IAM ROLE FOR SERVICE ACCOUNT
################################################################################
resource "aws_iam_policy" "cluster_autoscaler_policy_01" {
  name        = "eks-cluster-autoscaler-policy-01"
  description = "This Policy is for cluster autoscaler irsa permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [ "kms:Decrypt", "kms:GenerateData*", "kms:Encrypt" ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [ "autoscaling:SetDesiredCapacity" ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Action = [ "autoscaling:TerminateInstanceInAutoScalingGroup" ]
        Effect   = "Allow"
        Resource = [ 
          "*" 
        ]
      },
    ]
  })
  
}

module "cluster_autoscaler_irsa_01" {
  source  = "./modules/iam/sub-module/role-eks"
  role_name = "eks-cluster-autoscaler-irsa-01"
  attach_cluster_autoscaler_policy = true
  oidc_providers = {
    ex = {
      provider_arn               = "${module.cluster_01.oidc_provider_arn}"
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }

  role_policy_arns = {
    additional           = aws_iam_policy.cluster_autoscaler_policy_01.arn
  }

  
}

################################################################################
# BREx MT EKS CLUSTER KEYPAIR 
################################################################################
# module "cluster_kp_01" {
#   source     = "./modules/keypair"
#   key_name   = "eks-cluster-kp-01"
#   public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnPF7WQUxrPTe608i1GkkR0AhY4zQlcqHRIKXtv+sGgxvBGQyKPAyTleun2QIHdGA+u9m7IUMAbkHCfexA+leI+FBFFludrtSTdMKyYAtZd0i7SHJ7bHRbOOIicAf25YuwcOyaO1cnTq3ed3xEZjZs5UwzVstsBG4FdUAz6tf7toVobAUbv87GXrKvinpSVTtiamtNfoIu8Vcquc30lrVZ398GWIfGA+l0HBvgHoCl9cEyXaQB0fcQbiCye+tt8Rek7uwcrEcTQb4Mt9LgZexx+jqKXk3ENqHoJINFtNyl0QFJm1u2xs4MT4qph7HsYUpFqRU6ek0dQQeBsk8e1p6xRS6jd4b2RidsrH1+ohyDW6wCM2iaDQEv6yIlVPCWqM/aw/ced3rcWZnCt98MpeMXNvfkZuCkzVjdwTmMyA+ROVPpjZJifeZGqv/d7RJJcXuNXQor1gfF/tb81cro9NAE6osC104UQStpt1KJNxTSq9bHKFTPSxvnxiTq+qv43vE="
#   tags = merge(
#     
#     { "application" = "eks-cluster" },
#     { "tier" = "app" }
#   )
# }
################################################################################
# BREx MT EKS CLUSTER SECURITY GROUP
################################################################################
module "cluster_sg_01" {
  source = "./modules/security-group"
  name   = "eks-cluster-sg-01"
  vpc_id = "vpc-0ec690d7eef788c05"
  ingress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic to internal vpc range"
      cidr_blocks = "10.0.0.0/8"
    }
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
  tags = merge(
    
    { "application" = "eks-cluster" },
    { "tier" = "app" }
  )
}
################################################################################
# BREx MT EKS MANAGED NODE GROUP SECURITY GROUP
################################################################################
module "managed_node_sg_01" {
  source = "./modules/security-group"
  name   = "eks-managed-node-sg-01"
  vpc_id = "vpc-0ec690d7eef788c05"
  ingress_with_source_security_group_id = [
    {
      from_port   = 6443
      to_port     = 6443
      protocol    = "tcp"
      description = "Opening 6443 port from self sg"
      source_security_group_id = "${module.managed_node_sg_01.security_group_id}"
    },
    {
      from_port   = 2379
      to_port     = 2380
      protocol    = "tcp"
      description = "Opening 2379-2380 port from self sg"
      source_security_group_id = "${module.managed_node_sg_01.security_group_id}"
    },
    {
      from_port   = 10250
      to_port     = 10250
      protocol    = "tcp"
      description = "Opening 10250 port from self sg"
      source_security_group_id = "${module.managed_node_sg_01.security_group_id}"
    },
    {
      from_port   = 10259
      to_port     = 10259
      protocol    = "tcp"
      description = "Opening 10259 port from self sg"
      source_security_group_id = "${module.managed_node_sg_01.security_group_id}"
    },
    {
      from_port   = 10257
      to_port     = 10257
      protocol    = "tcp"
      description = "Opening 10257 port from self sg"
      source_security_group_id = "${module.managed_node_sg_01.security_group_id}"
    }
  ]
  ingress_with_cidr_blocks = [
   
  ]
  egress_with_cidr_blocks = [
    {
      from_port   = -1
      to_port     = -1
      protocol    = -1
      description = "allow all traffic"
      cidr_blocks = "0.0.0.0/0"
    },
  ]
  tags = merge(
    
    { "application" = "eks-cluster" },
    { "tier" = "app" }
  )
}
################################################################################
# BREx MT EKS MODULE
################################################################################
module "cluster_01" {
  source  = "./modules/eks"
  
  ## CLUSTER GENERAL INPUTS
  cluster_name                   = "eks-cluster-01"
  cluster_version                = "1.31"
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access = false
  ## CLUSTER ADDONS
  cluster_addons = {
    coredns = {
      most_recent              = true
    #   addon_version            = "v1.10.1-eksbuild.6"
    }
    kube-proxy = {
      most_recent              = true
    #   addon_version            = "v1.28.4-eksbuild.4"
    }
    vpc-cni = {
      most_recent              = true
    #   addon_version            = "v1.16.0-eksbuild.1"
      service_account_role_arn = module.vpc_cni_irsa_01.iam_role_arn
      configuration_values = jsonencode({
        env = {
          # Reference docs https:\docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
    aws-ebs-csi-driver ={
      most_recent              = true
    #   addon_version            = "v1.26.1-eksbuild.1"
      service_account_role_arn = module.ebs_csi_driver_irsa_01.iam_role_arn
    }
    aws-efs-csi-driver ={
      most_recent              = true
      #addon_version            = "v1.24.0-eksbuild.1"
      service_account_role_arn = module.efs_csi_driver_irsa_01.iam_role_arn
    }

  }
  
  ## CLUSTER NETWORKING
  vpc_id                   = "vpc-0ec690d7eef788c05"
  subnet_ids               = ["subnet-03d1e3b612358160f","subnet-038b007df470a88e6"]
  control_plane_subnet_ids = ["subnet-03d1e3b612358160f","subnet-038b007df470a88e6"]
  ## CLUSTER SECURITY
  cluster_security_group_id = "${module.managed_node_sg_01.security_group_id}"
  create_kms_key = true
  
  ## CLUSTER IAM ROLE
  iam_role_use_name_prefix = false
  iam_role_name = "eks-cluster-role-01"
  
  ## CLUSTER SG
  cluster_security_group_name = "eks-cluster-default-sg-01"
  cluster_security_group_use_name_prefix = false
  cluster_security_group_additional_rules = {
    ingress_internal_range = {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      description = "allowing port 443 from internal range for api communication"
      type = "ingress"
      cidr_blocks = ["10.32.0.0/16"]
    }
  }
  
  ## CLUSTER NODE SG
  node_security_group_name = "eks-cluster-default-node-sg-01"
  node_security_group_use_name_prefix = false
  node_security_group_tags = {
    "kubernetes.io/cluster/eks-cluster-01" = null
  }
  
  ## CLUSTER AWS AUTH CONFIGMAP
  create_aws_auth_configmap = false
  manage_aws_auth_configmap = false
  
}
#IAM POLICY FOR EKS NODE GROUP
resource "aws_iam_role" "managed_role" {
  name = "eks-managed-role-01"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ec2.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy", "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy", "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly", "arn:aws:iam::aws:policy/AmazonElasticFileSystemReadOnlyAccess", "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy", "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
  inline_policy {
    name = "eks-managed-ng-additional-policy-01"
    policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sts:AssumeRole",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = "kms:Decrypt",
        Resource = "*"
	    },
      {
          "Sid": "VisualEditor0",
          "Effect": "Allow",
          "Action": [
            "secretsmanager:GetSecretValue",
            "secretsmanager:DescribeSecret"
          ],
          "Resource": "*"
        },
        {
          "Sid": "VisualEditor1",
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:GenerateDataKey"
          ],
          "Resource": "*"
        }
    ]
  })
  }
}
locals{
    eks_userdata_brex_mt = <<-EOT
      MIME-Version: 1.0
      Content-Type: multipart/mixed; boundary="\"
      --\
      #!/bin/bash
      Content-Type: text/x-shellscript; charset="us-ascii"
      set -ex
      B64_CLUSTER_CA="${module.cluster_01.cluster_certificate_authority_data}"
      API_SERVER_URL="${module.cluster_01.cluster_endpoint}"
      /etc/eks/bootstrap.sh "${module.cluster_01.cluster_name}" --b64-cluster-ca $B64_CLUSTER_CA --apiserver-endpoint $API_SERVER_URL 
      
      --\--
  EOT
}
#LAUNCH TEMPLATE FOR BREx MT EKS NODE 01
module "lt_01" {
  source = "./modules/launch-template"
  # AUTOSCALING GROUP
  create = false
 
  # LAUNCH TEMPLATE
  name = "eks-lt-01"
  security_groups    = [module.managed_node_sg_01.security_group_id, module.cluster_01.cluster_primary_security_group_id]
  create_launch_template      = true
  update_default_version      = true
  launch_template_use_name_prefix = false 
  launch_template_name        = "eks-lt-01"
  image_id          = local.ami_id_brex_mt_eks_ng
  key_name          = "eks-bastion-app-ec2-kp-01"
  block_device_mappings = [
    {
      # Root volume
      device_name = "/dev/xvda"
      no_device   = 0
      ebs = {
        delete_on_termination = true
        volume_size           = 50
        volume_type           = "gp3"
      }
    }
  ]
  user_data         = base64encode(local.eks_userdata_brex_mt)
  metadata_options = {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 32
    instance_metadata_tags      = "enabled"
  }
  tag_specifications = [
      {
        resource_type = "instance"
        tags = merge(
          { "Name" = "eks-managed-ng-01"}
        )
      },
      {
        resource_type = "volume"
        tags = merge(
          
          { "Name" = "eks-managed-ng-01"}
        )
      },
    ]
}

#### NODE GROUP FOR BREx
module "managed_node_group_01" {
  source  = "./modules/eks/sub-module/eks-managed-node-group"
  # GENERAL
  name            = "eks-managed-ng-01"
  use_name_prefix = false
  cluster_name    = module.cluster_01.cluster_name
     
  #NETWORKING
  subnet_ids = ["subnet-03d1e3b612358160f","subnet-038b007df470a88e6"]
  
  # LAUNCH TEMPLATE
  create_launch_template = "false"
  use_custom_launch_template = "true"
  launch_template_id  = "${module.lt_01.launch_template_id}"
  launch_template_version = "1"
  ami_type = "CUSTOM"
  
  # CAPACITY
  instance_types = ["t2.micro"]
  min_size     = 1
  max_size     = 1
  desired_size = 1
  # IAM
  create_iam_role = false
  iam_role_arn = aws_iam_role.managed_role.arn
  iam_role_use_name_prefix = false
  iam_role_attach_cni_policy = true
}


