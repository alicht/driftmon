#!/usr/bin/env python3
"""
Driftmon - AI Model Output Drift Detection and Monitoring
Main CLI entrypoint for the driftmon tool
"""

import argparse
import sys
import os
import json
import yaml
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple


def canon_bytes(path: Path) -> str:
    """
    Normalize text/JSON/YAML content from a file.
    
    Args:
        path: Path to the file to canonicalize
        
    Returns:
        Normalized string representation of the file content
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    content = path.read_text(encoding='utf-8')
    suffix = path.suffix.lower()
    
    if suffix == '.json':
        # Parse and re-serialize JSON with sorted keys
        try:
            data = json.loads(content)
            return json.dumps(data, sort_keys=True, separators=(',', ':'))
        except json.JSONDecodeError:
            # If not valid JSON, treat as text
            pass
    
    elif suffix in ['.yaml', '.yml']:
        # Parse and re-serialize YAML with sorted keys
        try:
            data = yaml.safe_load(content)
            return yaml.dump(data, sort_keys=True, default_flow_style=False)
        except yaml.YAMLError:
            # If not valid YAML, treat as text
            pass
    
    # Default: normalize newlines for text files
    # Convert all line endings to Unix style
    return content.replace('\r\n', '\n').replace('\r', '\n')


def fingerprint(path: Path) -> Tuple[str, str]:
    """
    Generate a SHA-256 hash and canonical text for a file.
    
    Args:
        path: Path to the file to fingerprint
        
    Returns:
        Tuple of (hash, canonical_text)
    """
    canonical_text = canon_bytes(path)
    
    # Calculate SHA-256 hash of the canonical text
    hash_obj = hashlib.sha256()
    hash_obj.update(canonical_text.encode('utf-8'))
    hash_value = hash_obj.hexdigest()
    
    return (hash_value, canonical_text)


class Driftmon:
    """Main Driftmon application class"""
    
    def __init__(self, config_path: str = "driftmon.yml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.drift_dir = Path(".drift")
        self.artifacts_dir = self.drift_dir / "artifacts"
        
        self._ensure_directories()
        self._load_config()
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        self.drift_dir.mkdir(exist_ok=True)
        self.artifacts_dir.mkdir(exist_ok=True)
    
    def _load_config(self):
        """Load configuration from driftmon.yml"""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
            print(f"Loaded configuration from {self.config_path}")
        else:
            print(f"Warning: Configuration file {self.config_path} not found")
    
    def watch(self, paths: Optional[list] = None):
        """Start watching specified paths for drift"""
        watch_paths = paths or self.config.get('watch', [])
        print(f"Starting drift monitoring for: {watch_paths}")
        print("Hello driftmon! Watch mode activated.")
        # TODO: Implement actual watching logic
    
    def check(self, file_path: str):
        """Check a specific file for drift"""
        print(f"Checking {file_path} for drift...")
        print("Hello driftmon! Check mode activated.")
        # TODO: Implement drift checking logic
    
    def status(self):
        """Show current drift monitoring status"""
        print("Driftmon Status")
        print("-" * 40)
        print(f"Config file: {self.config_path}")
        print(f"Drift directory: {self.drift_dir}")
        print(f"Artifacts directory: {self.artifacts_dir}")
        
        if self.config:
            print(f"\nWatching: {self.config.get('watch', [])}")
            print(f"Ignoring: {self.config.get('ignore', [])}")
            print(f"Alerts enabled: {self.config.get('alerts', {}).get('enabled', False)}")
    
    def init(self):
        """Initialize driftmon in the current directory"""
        print("Initializing driftmon...")
        self._ensure_directories()
        
        # Create default config if it doesn't exist
        if not self.config_path.exists():
            print(f"Creating default configuration at {self.config_path}")
            # TODO: Create default config
        
        print("Hello driftmon! Initialization complete.")
    
    def hash(self, file_path: str):
        """Calculate and display hash of a file"""
        path = Path(file_path)
        
        try:
            hash_value, canonical_text = fingerprint(path)
            print(f"File: {file_path}")
            print(f"SHA-256: {hash_value}")
            print(f"Canonical size: {len(canonical_text)} bytes")
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error processing file: {e}")
            sys.exit(1)


def main():
    """Main CLI entrypoint"""
    parser = argparse.ArgumentParser(
        description="Driftmon - AI Model Output Drift Detection and Monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="driftmon 0.1.0"
    )
    
    parser.add_argument(
        "-c", "--config",
        default="driftmon.yml",
        help="Path to configuration file (default: driftmon.yml)"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize driftmon in current directory")
    
    # Watch command
    watch_parser = subparsers.add_parser("watch", help="Start watching for drift")
    watch_parser.add_argument(
        "paths",
        nargs="*",
        help="Paths to watch (overrides config file)"
    )
    
    # Check command
    check_parser = subparsers.add_parser("check", help="Check specific file for drift")
    check_parser.add_argument(
        "file",
        help="File path to check"
    )
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show drift monitoring status")
    
    # Hash command
    hash_parser = subparsers.add_parser("hash", help="Calculate hash of a file")
    hash_parser.add_argument(
        "file",
        help="File path to hash"
    )
    
    args = parser.parse_args()
    
    # Create driftmon instance
    driftmon = Driftmon(config_path=args.config)
    
    # Execute command
    if args.command == "init":
        driftmon.init()
    elif args.command == "watch":
        driftmon.watch(args.paths if args.paths else None)
    elif args.command == "check":
        driftmon.check(args.file)
    elif args.command == "status":
        driftmon.status()
    elif args.command == "hash":
        driftmon.hash(args.file)
    else:
        print("Hello driftmon!")
        print("Use --help to see available commands")
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()