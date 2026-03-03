.PHONY: help install install-dev test lint clean help

help:
	@echo "Docker Image Migration Tool - Development Commands"
	@echo ""
	@echo "Available targets:"
	@echo "  make install        - Install production dependencies"
	@echo "  make install-dev    - Install development dependencies"
	@echo "  make test           - Run test suite"
	@echo "  make lint           - Check code syntax"
	@echo "  make clean          - Remove generated files and caches"
	@echo "  make help           - Show this help message"
	@echo ""

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov

test:
	python -m pytest test_move_images.py -v

test-cov:
	python -m pytest test_move_images.py -v --cov=move_images --cov-report=html

lint:
	python -m py_compile move_images.py
	python -m py_compile test_move_images.py

clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov *.pyc
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete

cli-help:
	python move_images.py --help

version:
	@grep -E "^# Version:|# Date:" move_images.py | head -2 || echo "No version info found"
