# MEAT-GRINDER Development Commands

.PHONY: format lint check install-dev pre-commit

# Format all code with Black and isort
format:
	@echo "🎨 Formatting code with Black..."
	black .
	@echo "📦 Sorting imports with isort..."
	isort .
	@echo "✅ Formatting complete!"

# Run linting checks
lint:
	@echo "🔍 Running Flake8..."
	flake8 .
	@echo "🔍 Running MyPy..."
	mypy .

# Run both format and lint
check: format lint

# Install development dependencies
install-dev:
	pip install -r requirements.txt
	pre-commit install

# Run pre-commit on all files
pre-commit:
	pre-commit run --all-files

# Clean up generated files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
