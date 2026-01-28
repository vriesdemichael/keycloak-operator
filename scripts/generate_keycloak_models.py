#!/usr/bin/env python3
"""
Generate Pydantic models from Keycloak OpenAPI spec.

This script downloads the canonical Keycloak OpenAPI spec and generates
Pydantic models for type-safe API interactions.

Usage:
    uv run scripts/generate_keycloak_models.py

The generated models are placed in src/keycloak_operator/models/keycloak_api.py
"""

import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent
MODELS_DIR = PROJECT_ROOT / "src" / "keycloak_operator" / "models"
SPECS_DIR = SCRIPT_DIR / ".keycloak-specs"


def load_config() -> dict:
    """Load canonical version from config file."""
    config_path = SCRIPT_DIR / "keycloak_versions.yaml"
    if not config_path.exists():
        logger.error(f"Config file not found at {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        data = yaml.safe_load(f)
        return data.get("canonical_version", {})


def download_spec(version: str, url: str) -> Path:
    """Download OpenAPI spec if not exists."""
    SPECS_DIR.mkdir(parents=True, exist_ok=True)
    spec_path = SPECS_DIR / f"keycloak-api-{version}.yaml"

    logger.info(f"Checking spec for {version}...")

    try:
        if spec_path.exists() and spec_path.stat().st_size > 0:
            logger.info(f"Spec for {version} already exists at {spec_path}")
            return spec_path

        logger.info(f"Downloading spec from {url}...")
        response = httpx.get(url, follow_redirects=True, timeout=60.0)
        response.raise_for_status()

        spec_path.write_bytes(response.content)
        logger.info(f"Saved spec to {spec_path}")
        return spec_path
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to download spec for {version}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to download spec for {version}: {e}")
        sys.exit(1)


def generate_model(spec_path: Path, version: str) -> Path:
    """Generate Pydantic model for the canonical version."""
    output_file = MODELS_DIR / "keycloak_api.py"

    logger.info(f"Generating models from {spec_path.name}...")

    # Create a temporary directory for the generation process
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_spec_path = Path(tmp_dir) / spec_path.name
        tmp_output_path = Path(tmp_dir) / "keycloak_api.py"

        shutil.copy(spec_path, tmp_spec_path)

        # Command for datamodel-codegen
        cmd = [
            "uv",
            "run",
            "--no-project",
            "--python",
            "3.12",
            "--with",
            "datamodel-code-generator[http]",
            "datamodel-codegen",
            "--input",
            str(tmp_spec_path),
            "--output",
            str(tmp_output_path),
            "--input-file-type",
            "openapi",
            "--output-model-type",
            "pydantic_v2.BaseModel",
            "--use-standard-collections",
            "--use-schema-description",
            "--use-field-description",
            "--use-default",
            "--snake-case-field",
            "--target-python-version",
            "3.13",
            "--disable-timestamp",
            "--enum-field-as-literal",
            "one",
            "--field-constraints",
            "--use-annotated",
            "--use-double-quotes",
            "--use-union-operator",
            "--collapse-root-models",
            "--allow-population-by-field-name",
        ]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)

            # Post-processing: Add header to indicate it's generated
            content = tmp_output_path.read_text()
            header = f'''"""
Keycloak Admin REST API Models

Generated from Keycloak OpenAPI Spec version {version}
DO NOT EDIT MANUALLY - regenerate with: uv run scripts/generate_keycloak_models.py

These models represent the canonical Keycloak API types. The operator uses
version-specific adapters (see compatibility/ module) to handle differences
between Keycloak versions.
"""

'''
            tmp_output_path.write_text(header + content)

            shutil.move(tmp_output_path, output_file)
            logger.info(f"Generated {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate models:\n{e.stderr}")
            sys.exit(1)


def update_current_py(version: str):
    """Update current.py to document the canonical version."""
    current_file = MODELS_DIR / "current.py"

    logger.info(f"Updating current.py to document version {version}...")

    content = f'''"""
Canonical Keycloak API Models

This module re-exports all models from keycloak_api.py for convenient imports.
The models are generated from Keycloak OpenAPI spec version {version}.

All operator logic should be written against these models. Version-specific
differences are handled by the compatibility layer (see compatibility/ module).

Usage:
    from keycloak_operator.models.current import RealmRepresentation, ClientRepresentation
"""

# Re-export all models from keycloak_api.py
# This wildcard import is intentional - we want all generated models available
from .keycloak_api import *  # noqa: F401, F403
'''
    current_file.write_text(content)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Keycloak Pydantic models from OpenAPI spec."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force regeneration even if models exist",
    )
    args = parser.parse_args()

    canonical = load_config()
    if not canonical:
        logger.error("No canonical_version found in config!")
        sys.exit(1)

    version = canonical["version"]
    url = canonical["url"]

    logger.info(f"Canonical version: {version}")

    # Check if regeneration is needed
    output_file = MODELS_DIR / "keycloak_api.py"
    if output_file.exists() and not args.force:
        logger.info(
            f"Models already exist at {output_file}. Use --force to regenerate."
        )
        return

    spec_path = download_spec(version, url)
    generate_model(spec_path, version)
    update_current_py(version)

    logger.info("Model generation complete!")


if __name__ == "__main__":
    main()
