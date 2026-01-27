#!/usr/bin/env python3
import argparse
import logging
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

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
GENERATED_DIR = MODELS_DIR / "generated"
SPECS_DIR = SCRIPT_DIR / "keycloak-model-generation" / "specs"


def setup_directories():
    """Ensure necessary directories exist."""
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    SPECS_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure __init__.py exists in generated dir
    init_file = GENERATED_DIR / "__init__.py"
    if not init_file.exists():
        init_file.touch()


def load_config() -> list[dict[str, Any]]:
    """Load supported versions from config file."""
    config_path = SCRIPT_DIR / "keycloak_versions.yaml"
    if not config_path.exists():
        logger.error(f"Config file not found at {config_path}")
        sys.exit(1)

    with open(config_path) as f:
        data = yaml.safe_load(f)
        return data.get("supported_versions", [])


def download_spec(version: str, url: str) -> Path:
    """Download OpenAPI spec if not exists or hash changed."""
    spec_path = SPECS_DIR / f"keycloak-api-{version}.yaml"

    logger.info(f"Checking spec for {version}...")

    try:
        # Always fetch to check for updates (or we could rely on manual cleanup)
        # For now, we trust the file if it exists to save bandwidth/time,
        # unless forced (future improvement)
        if spec_path.exists() and spec_path.stat().st_size > 0:
            logger.info(f"Spec for {version} already exists.")
            return spec_path

        logger.info(f"Downloading spec from {url}...")
        response = httpx.get(url, follow_redirects=True)
        response.raise_for_status()

        spec_path.write_bytes(response.content)
        logger.info(f"Saved spec to {spec_path}")
        return spec_path
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            logger.warning(f"Spec not found for version {version} (404). Skipping.")
            return None
        logger.error(f"Failed to download spec for {version}: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to download spec for {version}: {e}")
        sys.exit(1)


def generate_model(spec_path: Path, module_name: str) -> Path:
    """Generate Pydantic model for a specific version."""
    output_file = GENERATED_DIR / f"{module_name}.py"

    if output_file.exists() and output_file.stat().st_size > 0:
        logger.info(f"Model {module_name} already exists. Skipping generation.")
        return output_file

    logger.info(f"Generating models for {module_name}...")

    # Create a temporary directory for the generation process
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_spec_path = Path(tmp_dir) / spec_path.name
        tmp_output_path = Path(tmp_dir) / f"{module_name}.py"

        shutil.copy(spec_path, tmp_spec_path)

        # Command matches the one used in the bash script but adapted for multiple files
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
            header = f"# Generated from Keycloak OpenAPI Spec {spec_path.name}\n# DO NOT EDIT MANUALLY\n\n"
            tmp_output_path.write_text(header + content)

            shutil.move(tmp_output_path, output_file)
            logger.info(f"Generated {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to generate models for {module_name}:\n{e.stderr}")
            sys.exit(1)


def create_current_symlink(current_version: dict):
    """Create the current.py file importing the current version."""
    module_name = current_version["module_name"]
    current_file = MODELS_DIR / "current.py"

    logger.info(f"Updating current.py to point to {module_name}...")

    content = f"""# Canonical Models for the Operator
# This file imports the models from the latest supported Keycloak version.
# All Operator logic should be written against these models.

from .generated.{module_name} import *
"""
    current_file.write_text(content)


def main():
    parser = argparse.ArgumentParser(description="Generate Keycloak Pydantic models.")
    parser.parse_args()

    setup_directories()
    versions = load_config()

    current_version = None

    for v in versions:
        spec_path = download_spec(v["version"], v["url"])
        if spec_path:
            generate_model(spec_path, v["module_name"])

        if v.get("current"):
            current_version = v

    if current_version:
        create_current_symlink(current_version)
    else:
        logger.warning("No version marked as 'current' in config!")


if __name__ == "__main__":
    main()
