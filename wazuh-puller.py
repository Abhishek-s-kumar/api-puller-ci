#!/usr/bin/env python3
"""
wazuh-puller.py - Pull rules from API server and deploy to Wazuh container
Usage: Run inside Wazuh container OR from host with docker exec
"""
import os
import sys
import json
import requests
import tarfile
import io
import shutil
import logging
from pathlib import Path
from datetime import datetime

# ==================== CONFIGURATION ====================
# These can be overridden by environment variables
CONFIG = {
    'api_url': os.getenv('API_URL', 'http://wazuh-api:8002'),
    'api_key': os.getenv('API_KEY', ''),
    'server_id': os.getenv('SERVER_ID', ''),
    'rules_path': os.getenv('RULES_PATH', '/var/ossec/etc/rules'),
    'decoders_path': os.getenv('DECODERS_PATH', '/var/ossec/etc/decoders'),
    'backup_path': os.getenv('BACKUP_PATH', '/tmp/wazuh-backup'),
    'log_file': os.getenv('LOG_FILE', '/var/log/wazuh-puller.log')
}

# ==================== LOGGING ====================
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(CONFIG['log_file'])
        ]
    )
    return logging.getLogger('wazuh-puller')

logger = setup_logging()

# ==================== API CLIENT ====================
class WazuhAPIClient:
    def __init__(self, api_url, api_key):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {
            'X-API-Key': api_key,
            'Accept': 'application/json'
        }

    def health_check(self):
        """Check API health"""
        try:
            response = requests.get(
                f"{self.api_url}/health",
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

    def list_rules(self):
        """Get list of available rules"""
        try:
            response = requests.get(
                f"{self.api_url}/api/rules/list",
                headers=self.headers,
                timeout=30
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

    def download_rules_package(self, format='tar'):
        """Download rules package from API"""
        try:
            response = requests.get(
                f"{self.api_url}/api/rules/package",
                headers=self.headers,
                stream=True,
                timeout=60
            )
            response.raise_for_status()

            # Save to temporary file
            content = response.content

            # Check if it's a tar file (magic bytes)
            if content[:2] == b'\x1f\x8b':  # gzip magic
                return True, content, 'tar.gz'
            else:
                # Assume it's raw files (for now)
                return True, content, 'raw'

        except Exception as e:
            return False, str(e), None

# ==================== FILE MANAGEMENT ====================
class FileManager:
    def __init__(self, rules_path, decoders_path, backup_path):
        self.rules_path = Path(rules_path)
        self.decoders_path = Path(decoders_path)
        self.backup_path = Path(backup_path)

        # Ensure directories exist
        self.rules_path.mkdir(parents=True, exist_ok=True)
        self.decoders_path.mkdir(parents=True, exist_ok=True)
        self.backup_path.mkdir(parents=True, exist_ok=True)

    def create_backup(self):
        """Create backup of current rules and decoders"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dir = self.backup_path / f"backup_{timestamp}"

        logger.info(f"Creating backup at: {backup_dir}")

        try:
            # Backup rules
            if self.rules_path.exists():
                rules_backup = backup_dir / 'rules'
                shutil.copytree(self.rules_path, rules_backup)

            # Backup decoders
            if self.decoders_path.exists():
                decoders_backup = backup_dir / 'decoders'
                shutil.copytree(self.decoders_path, decoders_backup)

            return str(backup_dir)
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            return None

    def extract_package(self, package_content, format='tar'):
        """Extract rules package"""
        try:
            if format == 'tar.gz':
                # Extract tar.gz
                with tarfile.open(fileobj=io.BytesIO(package_content), mode='r:gz') as tar:
                    tar.extractall('/tmp/wazuh-extract')
                extract_dir = Path('/tmp/wazuh-extract')
            else:
                # Assume content is JSON with file structure
                try:
                    data = json.loads(package_content.decode('utf-8'))
                    extract_dir = Path('/tmp/wazuh-extract')
                    extract_dir.mkdir(exist_ok=True)

                    # Save files from JSON
                    if 'rules' in data:
                        rules_dir = extract_dir / 'rules'
                        rules_dir.mkdir(exist_ok=True)
                        for filename, content in data['rules'].items():
                            (rules_dir / filename).write_text(content)

                    if 'decoders' in data:
                        decoders_dir = extract_dir / 'decoders'
                        decoders_dir.mkdir(exist_ok=True)
                        for filename, content in data['decoders'].items():
                            (decoders_dir / filename).write_text(content)
                except:
                    # If not JSON, assume it's direct tar content
                    with tarfile.open(fileobj=io.BytesIO(package_content), mode='r') as tar:
                        tar.extractall('/tmp/wazuh-extract')
                    extract_dir = Path('/tmp/wazuh-extract')

            return extract_dir
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return None

    def deploy_files(self, extract_dir):
        """Deploy extracted files to Wazuh directories"""
        extract_path = Path(extract_dir)
        rules_extracted = extract_path / 'rules'
        decoders_extracted = extract_path / 'decoders'

        rule_count = 0
        decoder_count = 0

        # Deploy rules
        if rules_extracted.exists():
            logger.info(f"Deploying rules to: {self.rules_path}")

            # Clear existing rules (optional - comment out if you want to keep)
            for file in self.rules_path.glob('*.xml'):
                file.unlink()

            # Copy new rules
            for file in rules_extracted.glob('*.xml'):
                shutil.copy2(file, self.rules_path / file.name)
                rule_count += 1

        # Deploy decoders
        if decoders_extracted.exists():
            logger.info(f"Deploying decoders to: {self.decoders_path}")

            # Clear existing decoders
            for file in self.decoders_path.glob('*.xml'):
                file.unlink()

            # Copy new decoders
            for file in decoders_extracted.glob('*.xml'):
                shutil.copy2(file, self.decoders_path / file.name)
                decoder_count += 1

        return rule_count, decoder_count

    def cleanup(self, extract_dir=None):
        """Clean up temporary files"""
        if extract_dir and Path(extract_dir).exists():
            shutil.rmtree(extract_dir, ignore_errors=True)

        # Remove old backups (keep last 5)
        backups = sorted(self.backup_path.glob('backup_*'))
        if len(backups) > 5:
            for old_backup in backups[:-5]:
                shutil.rmtree(old_backup, ignore_errors=True)

# ==================== MAIN PULLER ====================
class WazuhPuller:
    def __init__(self, config):
        self.config = config
        self.api_client = WazuhAPIClient(config['api_url'], config['api_key'])
        self.file_manager = FileManager(
            config['rules_path'],
            config['decoders_path'],
            config['backup_path']
        )

    def run(self, dry_run=False):
        """Main execution flow"""
        logger.info("=" * 60)
        logger.info(f"Wazuh Rules Puller - {self.config.get('server_id', 'unknown')}")
        logger.info("=" * 60)

        # 1. Check API health
        logger.info("Checking API health...")
        healthy, health_data = self.api_client.health_check()
        if not healthy:
            logger.error(f"API health check failed: {health_data}")
            return False

        logger.info(f"API Status: {health_data.get('status', 'unknown')}")

        # 2. Get available rules
        logger.info("Fetching available rules...")
        success, rules_data = self.api_client.list_rules()
        if success:
            logger.info(f"Available: {rules_data.get('count', 0)} deployments")
        else:
            logger.warning(f"Could not fetch rules list: {rules_data}")

        # 3. Create backup
        backup_dir = self.file_manager.create_backup()
        if backup_dir:
            logger.info(f"Backup created: {backup_dir}")
        else:
            logger.warning("Backup creation failed or skipped")

        if dry_run:
            logger.info("DRY RUN - No changes made")
            return True

        # 4. Download rules package
        logger.info("Downloading rules package...")
        success, package_content, format = self.api_client.download_rules_package()
        if not success:
            logger.error(f"Download failed: {package_content}")
            return False

        logger.info(f"Downloaded {len(package_content)} bytes ({format})")

        # 5. Extract package
        logger.info("Extracting package...")
        extract_dir = self.file_manager.extract_package(package_content, format)
        if not extract_dir:
            logger.error("Extraction failed")
            return False

        # 6. Deploy files
        logger.info("Deploying files...")
        rules_count, decoders_count = self.file_manager.deploy_files(extract_dir)

        # 7. Cleanup
        self.file_manager.cleanup(extract_dir)

        logger.info("=" * 60)
        logger.info("✅ DEPLOYMENT COMPLETE")
        logger.info(f"   Rules deployed: {rules_count}")
        logger.info(f"   Decoders deployed: {decoders_count}")
        logger.info(f"   Backup: {backup_dir}")
        logger.info("=" * 60)

        return True

# ==================== MAIN ====================
def main():
    import argparse

    parser = argparse.ArgumentParser(description='Wazuh Rules Puller')
    parser.add_argument('--dry-run', action='store_true', help='Simulate without changes')
    parser.add_argument('--api-url', help='Override API URL')
    parser.add_argument('--api-key', help='Override API Key')
    parser.add_argument('--server-id', help='Server identifier')

    args = parser.parse_args()

    # Update config with command line args
    if args.api_url:
        CONFIG['api_url'] = args.api_url
    if args.api_key:
        CONFIG['api_key'] = args.api_key
    if args.server_id:
        CONFIG['server_id'] = args.server_id

    # Validate API key
    if not CONFIG['api_key']:
        logger.error("API key is required. Set API_KEY environment variable or use --api-key")
        sys.exit(1)

    # Run puller
    puller = WazuhPuller(CONFIG)
    success = puller.run(dry_run=args.dry_run)

    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
