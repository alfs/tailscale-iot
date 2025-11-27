# Tailscale IoT ESP32 Build System

.PHONY: help setup config build clean clean-all flash monitor logs run validate all install-espidf-deps

# Default target
.DEFAULT_GOAL := help

# Configuration
PYTHON := python3
PIP := $(PYTHON) -m pip
CONFIG_FILE := esp32-ts.yaml
SECRETS_FILE := secrets.yaml
EXAMPLE_CONFIG := example-esp32-c3-tailscale.yaml
SECRETS_TEMPLATE := secrets.yaml.template

# Color output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Tailscale IoT ESP32 Build System$(NC)"
	@echo ""
	@echo "$(GREEN)Available targets:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-20s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(GREEN)Quick start:$(NC)"
	@echo "  make setup              # Install ESPHome"
	@echo "  make config             # Copy example configuration files"
	@echo "  # Edit $(SECRETS_FILE) with your credentials"
	@echo "  make build              # Build the firmware"
	@echo "  make flash              # Flash to device"
	@echo "  make monitor            # Monitor serial logs"

all: build ## Build the firmware

setup: ## Install ESPHome dependency
	@echo "$(BLUE)Installing dependencies...$(NC)"
	@if ! command -v esphome >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing ESPHome...$(NC)"; \
		$(PIP) install esphome || exit 1; \
	else \
		echo "$(GREEN)✓ ESPHome is already installed$(NC)"; \
	fi
	@echo "$(GREEN)✓ Setup complete$(NC)"

install-espidf-deps: ## Install ESP-IDF Python packages (run if build fails)
	@echo "$(BLUE)Installing ESP-IDF Python packages...$(NC)"
	@ESPIDF_PYTHON=$$(ls -t ~/.platformio/penv/.espidf-*/bin/python 2>/dev/null | head -1); \
	if [ -z "$$ESPIDF_PYTHON" ]; then \
		echo "$(RED)✗ ESP-IDF virtual environment not found$(NC)"; \
		echo "  Try running 'make build' first to create it."; \
		exit 1; \
	fi; \
	echo "  Using Python: $$ESPIDF_PYTHON"; \
	$$ESPIDF_PYTHON -m pip install -q idf-component-manager esp-idf-kconfig cryptography || exit 1; \
	echo "$(GREEN)✓ ESP-IDF packages installed$(NC)"

config: ## Copy example configuration files
	@echo "$(BLUE)Setting up configuration files...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		if [ -f $(EXAMPLE_CONFIG) ]; then \
			cp $(EXAMPLE_CONFIG) $(CONFIG_FILE); \
			echo "  $(GREEN)✓ Created $(CONFIG_FILE)$(NC)"; \
		else \
			echo "  $(RED)✗ Example config $(EXAMPLE_CONFIG) not found$(NC)"; \
			exit 1; \
		fi; \
	else \
		echo "  $(YELLOW)⚠ $(CONFIG_FILE) already exists, skipping$(NC)"; \
	fi
	@if [ ! -f $(SECRETS_FILE) ]; then \
		if [ -f $(SECRETS_TEMPLATE) ]; then \
			cp $(SECRETS_TEMPLATE) $(SECRETS_FILE); \
			echo "  $(GREEN)✓ Created $(SECRETS_FILE)$(NC)"; \
			echo "  $(YELLOW)⚠ Remember to edit $(SECRETS_FILE) with your credentials!$(NC)"; \
		else \
			echo "  $(RED)✗ Secrets template $(SECRETS_TEMPLATE) not found$(NC)"; \
			exit 1; \
		fi; \
	else \
		echo "  $(YELLOW)⚠ $(SECRETS_FILE) already exists, skipping$(NC)"; \
	fi

build: ## Build the firmware
	@echo "$(BLUE)Building firmware...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ] || [ ! -f $(SECRETS_FILE) ]; then \
		echo "$(RED)✗ Config or secrets file missing. Run 'make config' first.$(NC)"; \
		exit 1; \
	fi
	@esphome compile $(CONFIG_FILE)
	@echo "$(GREEN)✓ Build complete!$(NC)"
	@echo "$(YELLOW)Firmware location:$(NC) .esphome/build/*/firmware.bin"

flash: ## Flash firmware to device
	@echo "$(BLUE)Flashing firmware...$(NC)"
	@esphome upload $(CONFIG_FILE)

monitor: ## Show device logs
	@echo "$(BLUE)Showing logs...$(NC)"
	@esphome logs $(CONFIG_FILE)

logs: monitor ## Alias for 'monitor'

run: ## Build, flash, and monitor logs
	@echo "$(BLUE)Building, flashing, and monitoring...$(NC)"
	@esphome run $(CONFIG_FILE)

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@if [ -f $(CONFIG_FILE) ]; then \
		esphome clean $(CONFIG_FILE); \
	else \
		rm -rf .esphome; \
	fi
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean ## Clean build artifacts and configuration files
	@echo "$(BLUE)Removing configuration files...$(NC)"
	@rm -f $(CONFIG_FILE) $(SECRETS_FILE)
	@echo "$(GREEN)✓ All generated files removed$(NC)"

validate: ## Validate configuration without building
	@echo "$(BLUE)Validating configuration...$(NC)"
	@esphome config $(CONFIG_FILE)
	@echo "$(GREEN)✓ Configuration is valid$(NC)"
