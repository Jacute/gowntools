.PHONY: coverage

coverage:
	go test -coverprofile=coverage.out -count=50 -timeout=20s ./...
	go tool cover -html=coverage.out -o coverage.html