module "eks_bastion_ec2_01" {
  source                  = "./modules/ec2"
  name                    = "eks-bastion-ec2-01"
  ami                     = "ami-099340ab7490f8ef6"
  instance_type           = "t2.micro"
  subnet_id               = "subnet-03d1e3b612358160f"
  vpc_security_group_ids  = ["sg-0e43017f5f785de23"]
  iam_instance_profile    = aws_iam_instance_profile.ec2eks_access_instance_profile_01.name
  key_name                = "ganesh-test"
  root_volume_size        = 50
  enable_volume_tags      = true
  disable_api_termination = true
  tags = merge(
    
    { "application" = "bastion-app" },
    { "customer" = "mt" },
    { "tier" = "app" },
    { "teleport" = "-com-eks-bastion-app" }
  )
  volume_tags = merge(
    
    { "application" = "bastion-app" },
    { "customer" = "mt" },
    { "tier" = "app" },
    { "teleport" = "-eks-bastion-app" }
  )
}

resource "aws_iam_instance_profile" "ec2eks_access_instance_profile_01" {
  name = "ec2-eks-access-role-01"
  role = aws_iam_role.ec2eks_access_instance_role.name
  tags = merge(
  {"application"="session-manager"}
  )
}

resource "aws_iam_role_policy" "assume_role_policy_foreks_teleport_cross_account-01" {
  name = "assume-role-cross-account-policy-01"
  role = aws_iam_role.ec2eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "ec2_eks_policy" {
  name = "ec2-eks-policy-01"
  role = aws_iam_role.ec2eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor3",
            "Effect": "Allow",
            "Action": "eks:DescribeCluster",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "_s3_common_access_policy" {
  name = "comman-s3-bucket-policy"
  role = aws_iam_role.ec2eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
               "s3:GetObject",
               "s3:PutObject"
            ],
            "Resource": [
              "*"
            ]
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt",
                "kms:Encrypt"
            ],
            "Resource": [
              "*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "ec2_ecr_readonly_policy" {
  name = "-ec2-ecr-readonly-policy-01"
  role = aws_iam_role.ec2eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "ec2_ecr_write_policy" {
  name = "ec2-ecr-write-policy-01"
  role = aws_iam_role.ec2eks_access_instance_role.id
policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:PutImage"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

## CREATING POLICY FOR RETRIEVING SECRETS VALUE
resource "aws_iam_role_policy" "assume_role_policy_foreks_prisma_secrets_policy" {
  name = "eks-prisma-secret-policy-01"
  role = aws_iam_role.ec2eks_access_instance_role.id
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
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
}
EOF

}

resource "aws_iam_role" "ec2eks_access_instance_role" {
  name                = "ec2-eks-access-role-01"
  path               = "/system/"
  assume_role_policy  = data.aws_iam_policy_document.instance_assume_role_policy.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"]
  tags = merge(
  {"application"="session-manager"}
  )
}
data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}
