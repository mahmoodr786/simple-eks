data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "flow_logs_policy" {
  statement {
    sid = "LogGroupAccess"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams"
    ]

    resources = [
      "*",
    ]
  }
}

data "aws_iam_policy_document" "flow_logs_assume_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}

data "http" "get_public_ip" {
  url = "http://ipinfo.io/ip"
}

data "aws_instances" "node_group_node" {
  filter {
    name   = "tag:aws:eks:cluster-name"
    values = ["${var.cluster_name}"]
  }
  depends_on = [aws_eks_node_group.node_group]
}
data "aws_instance" "ec2_node" {
  instance_id = data.aws_instances.node_group_node.ids[0]
}