# ==============================================================================
# PROJECT SENTINEL - DEVSECOPS & KONG API GATEWAY MAKEFILE
# Target Web App: OWASP Juice Shop (v20.1.1) + Kong API Gateway (v3.6)
# ==============================================================================

# Variables
JUICE_SHOP_IMAGE := bkimminich/juice-shop:v20.1.1
KONG_IMAGE       := kong:3.6
COMPOSE_FILE     := docker-compose.yml
SERVICE_WEB      := web
SERVICE_GATEWAY  := gateway

# Color Palette for CLI Help
CYAN   := \033[36m
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
RESET  := \033[0m

.PHONY: help up down restart status logs routes clean web-pull web-logs test-request test-ratelimit

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
	@echo "$(YELLOW)Mục đích: Quản lý hạ tầng Kong API Gateway và OWASP Juice Shop (v20.1.1)$(RESET)"
	@echo ""
	@echo "$(GREEN)Cú pháp: make <tên-lệnh>$(RESET)"
	@echo ""
	@echo "$(YELLOW)Danh sách lệnh khả dụng:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)make %-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(CYAN)==============================================================================$(RESET)"
	@echo ""

## -----------------------------------------------------------------------------
## INFRASTRUCTURE & GATEWAY TARGETS
## -----------------------------------------------------------------------------

up: ## Khởi chạy toàn bộ hạ tầng (Juice Shop + Kong Gateway) trên cổng 8000
	@echo "$(CYAN)[+] Đang khởi chạy hạ tầng Kong Gateway và Juice Shop...$(RESET)"
	docker compose -f $(COMPOSE_FILE) up -d
	@echo "$(GREEN)[✔] Hạ tầng đã khởi chạy thành công!$(RESET)"
	@echo "$(GREEN)[✔] Kong Proxy Access:  http://localhost:8000$(RESET)"
	@echo "$(GREEN)[✔] Kong Admin API:     http://localhost:8001$(RESET)"

down: ## Dừng và gỡ bỏ toàn bộ container (Kong Gateway + Juice Shop)
	@echo "$(YELLOW)[!] Đang dừng các container hạ tầng...$(RESET)"
	docker compose -f $(COMPOSE_FILE) down
	@echo "$(GREEN)[✔] Đã dừng và gỡ bỏ các container!$(RESET)"

restart: ## Khởi động lại toàn bộ dịch vụ (Kong Gateway + Juice Shop)
	@echo "$(CYAN)[+] Đang khởi động lại toàn bộ dịch vụ...$(RESET)"
	docker compose -f $(COMPOSE_FILE) restart
	@echo "$(GREEN)[✔] Đã khởi động lại dịch vụ thành công!$(RESET)"

status: ## Kiểm tra trạng thái hoạt động và Health Check của các container
	@echo "$(CYAN)[+] Trạng thái các containers hạ tầng:$(RESET)"
	docker compose -f $(COMPOSE_FILE) ps

logs: ## Xem nhật ký (logs) thời gian thực của toàn bộ hệ thống
	@echo "$(CYAN)[+] Hiển thị logs toàn hệ thống (Nhấn Ctrl+C để thoát)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) logs -f

routes: ## Truy vấn danh sách Routes đang nạp trong Kong Admin API (Port 8001)
	@echo "$(CYAN)[+] Danh sách Routes đang hoạt động trong Kong Admin API:$(RESET)"
	@curl -s http://localhost:8001/routes | grep -o '"paths":\[[^]]*\]' || echo "$(YELLOW)Chưa thể kết nối tới Admin API 8001$(RESET)"

clean: ## Dọn dẹp hoàn toàn containers, volumes và Docker images của hệ thống
	@echo "$(RED)[!] Đang dọn dẹp containers, volumes và images...$(RESET)"
	docker compose -f $(COMPOSE_FILE) down --volumes --remove-orphans
	docker image rm -f $(JUICE_SHOP_IMAGE) $(KONG_IMAGE) || true
	@echo "$(GREEN)[✔] Đã dọn dẹp hoàn tất!$(RESET)"

## -----------------------------------------------------------------------------
## WEB BACKEND DEBUG TARGETS
## -----------------------------------------------------------------------------

web-pull: ## Tải Docker image OWASP Juice Shop v20.1.1 từ Docker Hub
	@echo "$(CYAN)[+] Đang tải Docker image $(JUICE_SHOP_IMAGE)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) pull $(SERVICE_WEB)
	@echo "$(GREEN)[✔] Đã tải xong Docker image Juice Shop!$(RESET)"

web-logs: ## Xem nhật ký (logs) thời gian thực riêng của container Juice Shop
	@echo "$(CYAN)[+] Hiển thị logs của Juice Shop (Nhấn Ctrl+C để thoát)...$(RESET)"
	docker compose -f $(COMPOSE_FILE) logs -f $(SERVICE_WEB)

## -----------------------------------------------------------------------------
## PYTHON TOOL TEST TARGETS
## -----------------------------------------------------------------------------

test-request: ## Gửi 1 HTTP request an toàn qua Gateway (VD: make test-request URL=/api/Quantitys METHOD=GET)
	@echo "$(CYAN)[+] Đang chạy Python Tool kiểm thử HTTP request...$(RESET)"
	@python3 tools/safe_requester.py --url $(or $(URL),/api/Quantitys) --method $(or $(METHOD),GET) $(if $(HEADERS),--headers '$(HEADERS)') $(if $(DATA),--data '$(DATA)')

test-ratelimit: ## Chạy burst test N request kiểm chứng Rate Limit 429 (VD: make test-ratelimit COUNT=25)
	@echo "$(CYAN)[+] Đang chạy Burst Rate Limit Test...$(RESET)"
	@python3 tools/safe_requester.py --url $(or $(URL),/api/Quantitys) --method $(or $(METHOD),GET) --count $(or $(COUNT),25)

