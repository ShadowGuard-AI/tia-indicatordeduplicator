# tia-IndicatorDeduplicator
Removes duplicate indicators from a list of threat intelligence feeds, outputting a unique set. Supports various indicator types (IPs, domains, URLs, hashes). - Focused on Aggregates threat intelligence data from various open-source feeds (e.g., blog posts, Twitter, RSS) into a unified, searchable format for proactive security analysis. Handles parsing, filtering, and basic analysis of gathered intelligence.

## Install
`git clone https://github.com/ShadowStrikeHQ/tia-indicatordeduplicator`

## Usage
`./tia-indicatordeduplicator [params]`

## Parameters
- `-h`: Show help message and exit
- `--log_level`: Set the logging level.
- `--indicator_type`: Specify the indicator type. Auto-detect if not specified.

## License
Copyright (c) ShadowStrikeHQ
