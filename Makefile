APP_NAME=rimaupanel
CMD_PATH=./cmd/rimaupanel

.PHONY: tidy fmt run build build-opt

tidy:
	go mod tidy

fmt:
	gofmt -w ./cmd ./internal

run:
	go run $(CMD_PATH)

build:
	mkdir -p ./bin
	go build -o ./bin/$(APP_NAME) $(CMD_PATH)

build-opt:
	mkdir -p /opt/rimaupanel
	go build -o /opt/rimaupanel/$(APP_NAME) $(CMD_PATH)
