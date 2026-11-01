import argparse
import logging
import re
import sys
from urllib.parse import urlparse, urlunparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regular expressions for indicator validation
IP_REGEX = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
DOMAIN_REGEX = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', re.IGNORECASE)
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http(s) or ftp(s)
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
HASH_REGEX = re.compile(r'^[a-f0-9]{32,128}$', re.IGNORECASE)  # Basic hash check

DEFAULT_PORTS = {'http': 80, 'https': 443, 'ftp': 21}


def normalize_indicator(indicator, indicator_type='auto'):
    """
    Normalizes an indicator before validation and deduplication:
    domains and hashes are case folded, a trailing dot is stripped
    from domains and URL hosts, and URLs get a lowercase scheme and
    host with any default port removed.
    """
    value = indicator.strip()

    if indicator_type == 'hash':
        return value.lower()
    if indicator_type == 'domain':
        return value.lower().rstrip('.')
    if indicator_type == 'ip':
        return value

    # URL normalization (explicit type or auto detection).
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or '').lower().rstrip('.')
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = host
        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo += f":{parsed.password}"
            netloc = f"{userinfo}@{netloc}"
        if port is not None and port != DEFAULT_PORTS.get(scheme):
            netloc = f"{netloc}:{port}"
        return urlunparse((scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))

    if HASH_REGEX.match(value):
        return value.lower()
    if DOMAIN_REGEX.match(value.lower().rstrip('.')):
        return value.lower().rstrip('.')
    return value


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Removes duplicate indicators from a list of threat intelligence feeds.')
    parser.add_argument('input_file', help='Path to the input file containing indicators (one indicator per line).')
    parser.add_argument('output_file', help='Path to the output file to store the unique indicators.')
    parser.add_argument('--log_level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set the logging level.')
    parser.add_argument('--indicator_type', default='auto', choices=['auto', 'ip', 'domain', 'url', 'hash'], help='Specify the indicator type. Auto-detect if not specified.')

    return parser


def validate_indicator(indicator, indicator_type='auto'):
    """
    Validates if an indicator matches the specified type.
    Args:
        indicator (str): The indicator to validate.
        indicator_type (str): The type of indicator to validate against (ip, domain, url, hash). Defaults to 'auto'.
    Returns:
        bool: True if the indicator is valid, False otherwise.
    """
    try:
        indicator = indicator.strip()  # Clean up whitespace

        if indicator_type == 'ip':
            return bool(IP_REGEX.match(indicator))
        elif indicator_type == 'domain':
            return bool(DOMAIN_REGEX.match(indicator))
        elif indicator_type == 'url':
            return bool(URL_REGEX.match(indicator))
        elif indicator_type == 'hash':
            return bool(HASH_REGEX.match(indicator))
        elif indicator_type == 'auto':
            return any([bool(IP_REGEX.match(indicator)),
                        bool(DOMAIN_REGEX.match(indicator)),
                        bool(URL_REGEX.match(indicator)),
                        bool(HASH_REGEX.match(indicator))])
        else:
            logging.error(f"Invalid indicator type specified: {indicator_type}")
            return False

    except Exception as e:
        logging.error(f"Error during indicator validation: {e}")
        return False


def process_indicators(input_file, output_file, indicator_type='auto'):
    """
    Reads indicators from the input file, removes duplicates, and writes the unique indicators to the output file.
    Args:
        input_file (str): Path to the input file.
        output_file (str): Path to the output file.
    """
    unique_indicators = set()
    dropped_count = 0

    with open(input_file, 'r') as infile:
        for line in infile:
            indicator = line.strip()
            if not indicator:  # Skip empty lines
                continue

            normalized = normalize_indicator(indicator, indicator_type)
            if validate_indicator(normalized, indicator_type):
                unique_indicators.add(normalized)  # Add to the set (duplicates are automatically removed)
            else:
                dropped_count += 1
                logging.warning(f"Invalid indicator found: {indicator}. Skipping.")

    if dropped_count:
        logging.warning(f"Dropped {dropped_count} invalid indicator(s).")

    if not unique_indicators:
        logging.error("No valid indicators were processed.")
        return 0

    with open(output_file, 'w') as outfile:
        for indicator in sorted(unique_indicators):  # Sorting for consistent output
            outfile.write(indicator + '\n')

    logging.info(f"Successfully processed {len(unique_indicators)} unique indicators.")
    return len(unique_indicators)


def main():
    """
    Main function to parse arguments and process the indicators.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    logging.debug("Starting indicator deduplication...")

    try:
        processed = process_indicators(args.input_file, args.output_file, args.indicator_type)
    except FileNotFoundError:
        logging.error(f"Input file not found: {args.input_file}")
        sys.exit(1)
    except IOError as e:
        logging.error(f"IOError: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)

    if not processed:
        logging.error("Indicator deduplication did not process any valid indicators.")
        sys.exit(1)

    logging.debug("Indicator deduplication completed.")


if __name__ == "__main__":
    # Usage example:
    # Create an input file named 'input.txt' with the following content:
    # 192.168.1.1
    # example.com
    # http://example.com/path
    # 192.168.1.1
    # another.com
    # 8.8.8.8
    #
    # Run the script from the command line:
    # python main.py input.txt output.txt --log_level=DEBUG
    #
    # An output file named 'output.txt' will be created with the unique indicators:
    # 192.168.1.1
    # 8.8.8.8
    # another.com
    # example.com
    # http://example.com/path
    main()