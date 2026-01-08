.PHONY: coverage

GREEN  := \033[0;32m
PURPLE := \033[0;35m
RESET  := \033[0m
RED    := \033[0;31m

TEST_EXCLUDE = 'examples|testsuite'
COVERAGE_SCHEMA_FILE = coverage.out
COVERAGE_HTML_FILE = coverage.html

coverage:
	@echo "$(GREEN)Running tests...$(RESET)"
	
	@PKGS=$$(go list ./... | grep -vE ${TEST_EXCLUDE} || true) && \
	if [ -z "$$PKGS" ]; then echo "No packages found in jacfarm-api"; exit 0; fi && \
	CSV=$$(echo $$PKGS | tr ' ' ',') && \
	echo -e "Running go tests for:\n$(PURPLE)$$PKGS$(RESET)" && \
	go test -tags=ci -coverpkg=$$CSV -coverprofile=${COVERAGE_SCHEMA_FILE} -timeout=40s $$PKGS
	@go tool cover -html=${COVERAGE_SCHEMA_FILE} -o ${COVERAGE_HTML_FILE} && \
	echo "$(GREEN)Coverage saved to ${COVERAGE_HTML_FILE}$(RESET)"