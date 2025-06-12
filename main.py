import argparse
import logging
import hashlib
import re
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Regular expressions for indicator validation
IP_REGEX = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
DOMAIN_REGEX = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
URL_REGEX = re.compile(
    r'^(?:http|ftp)s?://'  # http(s) or ftp(s)
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
    r'localhost|'  # localhost
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)
HASH_REGEX = re.compile(r'^[a-f0-9]{32,128}$')  # Basic hash check


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

    try:
        with open(input_file, 'r') as infile:
            for line in infile:
                indicator = line.strip()
                if not indicator:  # Skip empty lines
                    continue

                if validate_indicator(indicator, indicator_type):
                    unique_indicators.add(indicator)  # Add to the set (duplicates are automatically removed)
                else:
                    logging.warning(f"Invalid indicator found: {indicator}. Skipping.")

        with open(output_file, 'w') as outfile:
            for indicator in sorted(unique_indicators):  # Sorting for consistent output
                outfile.write(indicator + '\n')

        logging.info(f"Successfully processed {len(unique_indicators)} unique indicators.")

    except FileNotFoundError:
        logging.error(f"Input file not found: {input_file}")
    except IOError as e:
        logging.error(f"IOError: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def main():
    """
    Main function to parse arguments and process the indicators.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set logging level
    logging.getLogger().setLevel(args.log_level.upper())

    logging.debug("Starting indicator deduplication...")

    process_indicators(args.input_file, args.output_file, args.indicator_type)

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