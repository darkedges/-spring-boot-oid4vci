# One command per recipe works under Windows cmd, PowerShell, and sh.
PWSH ?= pwsh
.DEFAULT_GOAL := help
.PHONY: help env doctor setup keys passport-key db-up db-down run start phone build test
help env doctor setup keys passport-key db-up db-down run start phone build test:
	@$(PWSH) -NoLogo -NoProfile -File tools/Bank.ps1 -Task $@
