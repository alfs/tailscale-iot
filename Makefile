# Tailscale IoT ESP32 Build System
#
# This Makefile automates dependency checking, installation, and building
# of the Tailscale IoT firmware for ESP32 devices.

.PHONY: help setup check-deps install-deps init-submodules config build clean flash monitor logs all

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
	@echo "  make setup              # Install all dependencies and initialize submodules"
	@echo "  make config             # Copy example configuration files"
	@echo "  # Edit $(SECRETS_FILE) with your credentials"
	@echo "  make build              # Build the firmware (first build sets up ESP-IDF)"
	@echo "  make install-espidf-deps # Install ESP-IDF Python packages (if build fails)"
	@echo ""

all: check-deps init-submodules build ## Run full build pipeline (check deps, init submodules, build)

setup: install-deps init-submodules ## Install dependencies and initialize submodules
	@echo "$(GREEN)✓ Setup complete!$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Run 'make config' to copy example configuration files"
	@echo "  2. Edit $(SECRETS_FILE) with your credentials"
	@echo "  3. Run 'make build' to build the firmware"
	@echo "  4. If build fails with missing packages, run 'make install-espidf-deps'"

check-deps: ## Check if all required dependencies are installed
	@echo "$(BLUE)Checking dependencies...$(NC)"
	@$(MAKE) -s check-python
	@$(MAKE) -s check-esphome
	@$(MAKE) -s check-python-packages
	@$(MAKE) -s check-submodules
	@echo "$(GREEN)✓ All dependencies are installed$(NC)"

check-python: ## Check if Python 3 is installed
	@if ! command -v $(PYTHON) >/dev/null 2>&1; then \
		echo "$(RED)✗ Python 3 not found$(NC)"; \
		echo "  Install: apt-get install python3 (Debian/Ubuntu)"; \
		echo "           brew install python3 (macOS)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ Python 3 found:$(NC) $$($(PYTHON) --version)"

check-esphome: ## Check if ESPHome is installed
	@if ! command -v esphome >/dev/null 2>&1; then \
		echo "$(RED)✗ ESPHome not found$(NC)"; \
		echo "  Install: pip install esphome"; \
		echo "           brew install esphome (macOS)"; \
		echo "           pipx install esphome"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ ESPHome found:$(NC) $$(esphome version)"

check-python-packages: ## Check if required Python packages are installed
	@echo "$(BLUE)Checking Python packages...$(NC)"
	@if [ -f ~/.platformio/penv/.espidf-*/bin/python ]; then \
		ESPIDF_PYTHON=$$(ls -t ~/.platformio/penv/.espidf-*/bin/python 2>/dev/null | head -1); \
		if [ -n "$$ESPIDF_PYTHON" ]; then \
			missing_packages=""; \
			for package in idf_component_manager esp_idf_kconfig cryptography; do \
				if ! $$ESPIDF_PYTHON -c "import $$package" >/dev/null 2>&1; then \
					echo "  $(YELLOW)✗ $$package not found in ESP-IDF venv$(NC)"; \
					missing_packages="$$missing_packages $$package"; \
				else \
					echo "  $(GREEN)✓ $$package$(NC)"; \
				fi; \
			done; \
			if [ -n "$$missing_packages" ]; then \
				echo "$(YELLOW)Missing ESP-IDF packages:$$missing_packages$(NC)"; \
				echo "$(YELLOW)Run 'make install-espidf-deps' to install them$(NC)"; \
				exit 1; \
			fi; \
		fi; \
	else \
		echo "  $(YELLOW)⚠ ESP-IDF venv not found yet (will be created on first build)$(NC)"; \
	fi

check-submodules: ## Check if required submodules are initialized
	@echo "$(BLUE)Checking submodules...$(NC)"
	@if [ ! -f external/required/noise-c/library.json ]; then \
		echo "  $(YELLOW)✗ Required submodule noise-c not initialized$(NC)"; \
		echo "$(YELLOW)Run 'make init-submodules' to initialize them$(NC)"; \
		exit 1; \
	fi
	@echo "$(GREEN)✓ Required submodules initialized$(NC)"

install-deps: ## Install all required Python dependencies
	@echo "$(BLUE)Installing Python dependencies...$(NC)"
	@if ! command -v esphome >/dev/null 2>&1; then \
		echo "$(YELLOW)Installing ESPHome...$(NC)"; \
		$(PIP) install esphome || exit 1; \
	fi
	@echo "$(GREEN)✓ ESPHome installed$(NC)"
	@echo "$(YELLOW)Note: Run 'make install-espidf-deps' after first build to install ESP-IDF packages$(NC)"

install-espidf-deps: ## Install ESP-IDF Python packages in PlatformIO venv
	@echo "$(BLUE)Installing ESP-IDF Python packages...$(NC)"
	@ESPIDF_PYTHON=$$(ls -t ~/.platformio/penv/.espidf-*/bin/python 2>/dev/null | head -1); \
	if [ -z "$$ESPIDF_PYTHON" ]; then \
		echo "$(RED)✗ ESP-IDF virtual environment not found$(NC)"; \
		echo "  The ESP-IDF venv is created during the first build."; \
		echo "  Try running 'make build' first (it may fail), then run this command again."; \
		exit 1; \
	fi; \
	echo "  Using Python: $$ESPIDF_PYTHON"; \
	$$ESPIDF_PYTHON -m pip install -q idf-component-manager esp-idf-kconfig cryptography || exit 1; \
	echo "$(GREEN)✓ ESP-IDF packages installed:$(NC)"; \
	echo "  • idf-component-manager (for ESP-IDF components)"; \
	echo "  • esp-idf-kconfig (for menuconfig)"; \
	echo "  • cryptography (for certificate bundle generation)"

init-submodules: ## Initialize required git submodules (excludes optional ones)
	@echo "$(BLUE)Initializing required submodules...$(NC)"
	@git submodule update --init external/required/noise-c
	@echo "$(GREEN)✓ Required submodules initialized$(NC)"
	@echo "$(YELLOW)Note: Optional submodules for protocol debugging were not initialized$(NC)"
	@echo "      Run 'git submodule update --init --recursive' to get all submodules"

init-submodules-all: ## Initialize ALL git submodules including optional ones
	@echo "$(BLUE)Initializing all submodules (including optional)...$(NC)"
	@git submodule update --init --recursive
	@echo "$(GREEN)✓ All submodules initialized$(NC)"

config: ## Copy example configuration files
	@echo "$(BLUE)Setting up configuration files...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		if [ -f $(EXAMPLE_CONFIG) ]; then \
			echo "  Copying $(EXAMPLE_CONFIG) to $(CONFIG_FILE)"; \
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
			echo "  Copying $(SECRETS_TEMPLATE) to $(SECRETS_FILE)"; \
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

build: check-deps ## Build the firmware
	@echo "$(BLUE)Building firmware...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(RED)✗ Configuration file $(CONFIG_FILE) not found$(NC)"; \
		echo "  Run 'make config' to create it"; \
		exit 1; \
	fi
	@if [ ! -f $(SECRETS_FILE) ]; then \
		echo "$(RED)✗ Secrets file $(SECRETS_FILE) not found$(NC)"; \
		echo "  Run 'make config' to create it, then edit with your credentials"; \
		exit 1; \
	fi
	@esphome compile $(CONFIG_FILE)
	@echo "$(GREEN)✓ Build complete!$(NC)"
	@echo "$(YELLOW)Firmware location:$(NC) .esphome/build/*/firmware.bin"

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning build artifacts...$(NC)"
	@if [ -f $(CONFIG_FILE) ]; then \
		esphome clean $(CONFIG_FILE); \
	else \
		echo "$(YELLOW)No config file found, removing .esphome directory$(NC)"; \
		rm -rf .esphome; \
	fi
	@echo "$(GREEN)✓ Clean complete$(NC)"

clean-all: clean ## Clean build artifacts and configuration files
	@echo "$(BLUE)Removing configuration files...$(NC)"
	@rm -f $(CONFIG_FILE) $(SECRETS_FILE)
	@echo "$(GREEN)✓ All generated files removed$(NC)"

flash: ## Flash firmware to device (will prompt for device selection)
	@echo "$(BLUE)Flashing firmware...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(RED)✗ Configuration file $(CONFIG_FILE) not found$(NC)"; \
		exit 1; \
	fi
	@esphome upload $(CONFIG_FILE)

run: ## Build, flash, and monitor logs
	@echo "$(BLUE)Building, flashing, and monitoring...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(RED)✗ Configuration file $(CONFIG_FILE) not found$(NC)"; \
		exit 1; \
	fi
	@esphome run $(CONFIG_FILE)

logs: ## Show device logs
	@echo "$(BLUE)Showing logs...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(RED)✗ Configuration file $(CONFIG_FILE) not found$(NC)"; \
		exit 1; \
	fi
	@esphome logs $(CONFIG_FILE)

validate: ## Validate configuration without building
	@echo "$(BLUE)Validating configuration...$(NC)"
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "$(RED)✗ Configuration file $(CONFIG_FILE) not found$(NC)"; \
		exit 1; \
	fi
	@esphome config $(CONFIG_FILE)
	@echo "$(GREEN)✓ Configuration is valid$(NC)"

monitor: logs ## Alias for 'logs' target
