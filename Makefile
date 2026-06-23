# Convenience targets. `make serve` starts the web app; `make scan` runs the CLI.
.PHONY: install serve scan test

install:
	uv sync

serve: install
	uv run uvicorn sgai.api:app --host 0.0.0.0 --port $${PORT:-8080}

scan: install
	uv run sgai scan examples/vulnerable_app

test: install
	uv run pytest -q
