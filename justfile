isort:
    uvx isort --length-sort --profile=black --line-length=120 ucutils tests scripts

black:
    uvx black --line-length=120 ucutils tests scripts

ruff:
    uvx ruff check --line-length=120 ucutils tests scripts

flake8:
    uvx flake8 --max-line-length=120 --ignore=E203 ucutils tests scripts

mypy:
    uvx mypy --check-untyped-defs --ignore-missing-imports ucutils tests scripts

lint:
    -just isort
    -just black
    -just ruff
    -just flake8
    -just mypy
