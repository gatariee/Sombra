BIN_NAME = sombra
BIN_FOLDER = ../bin

.PHONY: all

all:
	@echo "[-] no target specified, available: win[64/32] | nix[64/32] | clean"

win64:
	@echo "[+] Building Windows x64"
	@set GOOS=windows&& set GOARCH=amd64&& go build -o ./$(BIN_FOLDER)/$(BIN_NAME)64.exe

win32:
	@echo "[+] Building Windows x32"
	@set GOOS=windows&& set GOARCH=386&& go build -o ./$(BIN_FOLDER)/$(BIN_NAME)32.exe
nix64:
	@echo "[+] Building Linux x64"
	@GOOS=linux GOARCH=amd64 go build -o $(BIN_FOLDER)/$(BIN_NAME)_nix64

nix32:
	@echo "[+] Building Linux x32"
	@GOOS=linux GOARCH=386 go build -o $(BIN_FOLDER)/$(BIN_NAME)_nix32
