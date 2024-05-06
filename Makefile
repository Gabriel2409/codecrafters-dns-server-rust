.PHONY: help dig 

# Display help message
help:
	@echo "Available targets:"
	@echo "  - help: Display this help message."
	@echo "  - dig: sends a dig request to local dns server" 

# noedns is used so that we stick to original format
# see https://github.com/EmilHernvall/dnsguide/blob/b52da3b32b27c81e5c6729ac14fe01fef8b1b593/chapter1.md
dig:
	dig @127.0.0.1 -p 2053 +noedns codecrafters.io


