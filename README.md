# sql_anon_dmp

MariaDB anonymizing/obfuscating dumper.

## Requirements

[pixi](https://pixi.prefix.dev/latest/) is required to run this package.

### Install pixi

```bash
curl -fsSL https://pixi.sh/install.sh | sh
```

See the [official installation guide](https://pixi.prefix.dev/latest/installation) for more options.

## Usage

### Install dependencies

```bash
pixi install
```

### Run the script

```bash
# Using a custom configuration file
pixi run run --config config.json

# Or with the hard-coded default configuration (non-functional example)
pixi run run
```

### Direct Python execution

```bash
pixi run python src/mariadb_anon_dump.py [--config config.json]
```

### Show help

```bash
pixi run run --help
```

## Configuration

A template configuration file is provided at `src/template.config.json` with example settings.

You can also edit the `CONFIG` dictionary in `src/mariadb_anon_dump.py` directly, but note that the hard-coded default contains placeholder values and is non-functional. It is recommended to use a JSON configuration file via the `--config` argument.

The script supports:
- Anonymization (bijective character substitution for strings)
- Obfuscation (linear transformation y = a * x for numbers)
- Column removal
- Row filtering via WHERE clauses

## Dependencies

- Python 3.14
- pymysql
- cryptography (required for sha256_password / caching_sha2_password authentication)
