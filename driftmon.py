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
from pathlib import Path
from typing import Dict, Any, Optional


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
    else:
        print("Hello driftmon!")
        print("Use --help to see available commands")
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()