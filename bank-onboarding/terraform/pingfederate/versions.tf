terraform {
  required_version = ">= 1.7, < 2.0"
  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "= 1.12.0"
    }
  }
}
