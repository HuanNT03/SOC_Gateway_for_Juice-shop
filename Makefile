# ==============================================================================
# PROJECT SENTINEL - DEVSECOPS & AI GATEWAY MAKEFILE
# Target Web App: OWASP Juice Shop (v20.1.1)
# ==============================================================================

# Variables
JUICE_SHOP_IMAGE := bkimminich/juice-shop:v20.1.1
COMPOSE_FILE     := docker-compose.yml
SERVICE_WEB      := web

# Color Palette for CLI Help
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
RESET  := \033[0m

.PHONY: help web-pull web-up web-down web-restart web-logs web-status web-clean

# Default target when running 'make' without arguments
.DEFAULT_GOAL := help

## -----------------------------------------------------------------------------
## HELP SYSTEM
## -----------------------------------------------------------------------------

help: ## Hiển thị menu hướng dẫn các lệnh trong Makefile
	@echo ""
	@echo "$(CYAN)==============================================================================$(RESET)"
	@echo "$(CYAN)                     PROJECT SENTINEL - MAKEFILE CLI                           $(RESET)"
	@echo "$(CYAN)==============================================================================$(RESET)"
	@echo "$(YELLOW)Mục đích: Quản lý ứng dụng thử nghiệm OWASP Juice Shop (v20.1.1)$(RESET)"
	@echo ""
	@echo "$(GREEN)Cú pháp: make <tên-lệnh>$(RESET)"
	@echo ""
	@echo "$(YELLOW)Danh sách lệnh khả dụng:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)make %-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)==============================================================================$(RESET)"
	@echo ""

## -----------------------------------------------------------------------------
## WEB TARGET MANAGEMENT (OWASP Juice Shop v20.1.1)
## -----------------------------------------------------------------------------

web-pull: ## Tải Docker image OWASP Juice Shop v20.1.1 từ Docker Hub
	@echo "$(CYAN)[+] Đang tải Docker image $(JUICE_SHOP_IMAGE)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) pull $(SERVICE_WEB)
	@echo "$(GREEN)[✔] Đã tải xong Docker image Juice Shop!$(RESET)"

web-up: ## Khởi chạy container Juice Shop chạy ngầm (detached mode) trên cổng 3000
	@echo "$(CYAN)[+] Đang khởi chạy OWASP Juice Shop (v20.1.1)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) up -d $(SERVICE_WEB)
	@echo "$(GREEN)[✔] Juice Shop đã khởi chạy thành công tại http://localhost:3000$(RESET)"

web-down: ## Dừng và gỡ bỏ container Juice Shop
	@echo "$(YELLOW)[!] Đang dừng container Juice Shop...$(RESET)"
	docker compose -f $(COMPOSE_FILE) stop $(SERVICE_WEB)
	docker compose -f $(COMPOSE_FILE) rm -f $(SERVICE_WEB)
	@echo "$(GREEN)[✔] Đã dừng và gỡ bỏ container Juice Shop!$(RESET)"

web-restart: ## Khởi động lại service Juice Shop
	@echo "$(CYAN)[+] Đang khởi động lại service Juice Shop...$(RESET)"
	docker compose -f $(COMPOSE_FILE) restart $(SERVICE_WEB)
	@echo "$(GREEN)[✔] Đã khởi động lại Juice Shop!$(RESET)"

web-logs: ## Xem nhật ký (logs) thời gian thực của container Juice Shop
	@echo "$(CYAN)[+] Hiển thị logs của Juice Shop (Nhấn Ctrl+C để thoát)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) logs -f $(SERVICE_WEB)

web-status: ## Kiểm tra trạng thái hoạt động và Health Check của Juice Shop container
	@echo "$(CYAN)[+] Trạng thái container Juice Shop:$(RESET)"
	docker compose -f $(COMPOSE_FILE) ps $(SERVICE_WEB)

web-clean: ## Dừng container, xóa network và dọn dẹp Docker cache/images Juice Shop
	@echo "$(RED)[!] Đang dọn dẹp container, network và image Juice Shop...$(RESET)"
	docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans
	docker image rm -f $(JUICE_SHOP_IMAGE) || true
	@echo "$(GREEN)[✔] Đã dọn dẹp hoàn tất!$(RESET)"
