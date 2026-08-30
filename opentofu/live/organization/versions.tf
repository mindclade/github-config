terraform {
  required_version = ">= 1.12.0, < 1.13.0"

  required_providers {
    github = {
      source  = "integrations/github"
      version = "= 6.13.0"
    }
  }
}
