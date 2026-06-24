.PHONY: up up-fresh down build test lint scan fmt pr-check evadex-scan evadex-status evadex-watch

up:
	./scripts/lab-up.sh --no-build

up-fresh:
	./scripts/lab-up.sh

down:
	./scripts/lab-down.sh

build:
	cargo build --release

test:
	cargo test --lib
	cargo test --test integration_test
	cargo test --test evasion_test

lint:
	cargo clippy --lib -- -D warnings -A dead-code -A unused-imports
	cargo fmt --check

scan:
	cd ../evadex && python -m evadex scan \
		--transport http \
		--url http://localhost:8080/api \
		--tier northam --fast \
		--scanner-label siphon-dev

fmt:
	cargo fmt

pr-check: lint test
	@echo "✓ Ready for PR"

evadex-scan:
	cd ../evadex && python -m evadex scan \
		--transport http \
		--url http://localhost:8080/api \
		--tier northam --fast \
		--scanner-label siphon-dev

evadex-status:
	cd ../evadex && python -m evadex status

evadex-watch:
	cd ../evadex && python -m evadex watch \
		--transport http \
		--url http://localhost:8080/api \
		--tier northam
