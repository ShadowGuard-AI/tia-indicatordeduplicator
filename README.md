# tia-IndicatorDeduplicator
Removes duplicate indicators from a list of threat intelligence feeds, outputting a unique set. Supports various indicator types (IPs, domains, URLs, hashes). - Focused on Aggregates threat intelligence data from various open-source feeds (e.g., blog posts, Twitter, RSS) into a unified, searchable format for proactive security analysis. Handles parsing, filtering, and basic analysis of gathered intelligence.

## Install
`git clone https://github.com/ShadowGuard-AI/tia-indicatordeduplicator`

This tool uses only the Python standard library, so there are no packages to install.

## Usage
`python main.py input_file output_file`

Indicators are normalized before deduplication: domains and hashes are case folded, a trailing dot is stripped from domains, and URLs get a lowercase scheme and host with any default port removed. Uppercase variants therefore deduplicate against their lowercase forms instead of being dropped. Entries that are still invalid after normalization are counted and reported as dropped. A missing input file, or an input with zero valid indicators, exits non-zero with no success message.

## Parameters
- `input_file` (required, positional): Path to the input file containing indicators (one indicator per line).
- `output_file` (required, positional): Path to the output file to store the unique indicators.
- `-h`: Show help message and exit
- `--log_level`: Set the logging level.
- `--indicator_type`: Specify the indicator type. Auto-detect if not specified.

## License
Copyright (c) ShadowGuard-AI
