# Flow Log Parser

## Overview
The **Flow Log Parser** is a simple Python tool designed to analyze AWS VPC flow logs. It helps categorize network traffic by mapping logs to predefined tags based on a lookup table. The parser then generates a clear summary of tag counts and port/protocol occurrences, making network monitoring more manageable.

## How to Run
Getting started is easy! Just follow these steps:
1. Ensure you have **Python 3.x** installed.
2. Clone this repository:
   ```sh
   git clone https://github.com/chandan25809/Flow-Log-Parser.git
   cd flow_log_parser
   ```
3. Run the script:
   ```sh
   python flow_log_parser.py
   ```
   Once completed, the results will be saved in `output_results.txt`.

## Assumptions
To keep things simple and efficient, we made the following assumptions:
- The parser **only supports AWS VPC Flow Log Version 2**.
- Any **invalid or malformed logs are skipped** to ensure accuracy.
- If a log entry **does not match any tag**, it is labeled as **Untagged**.
- Duplicate logs are processed and counted separately.
- The output file does not follow a strict order.

## Running Tests
We’ve built a suite of tests to ensure everything runs smoothly. Run the tests with:
```sh
python -m unittest test_flow_log_parser.py
```
This will validate that logs are processed correctly and that the output is as expected.

## What Was Tested
The parser was tested thoroughly to ensure its reliability:
- **Valid log entries:** Ensured correctly formatted logs are processed as expected.
- **Invalid log entries:** Verified that malformed or incomplete logs are skipped.
- **Empty log file:** Checked that an empty file does not cause errors.
- **Duplicate logs:** Ensured that duplicates are counted separately.
- **Malformed lookup table:** Checked that lookup table entries with missing fields are ignored.
- **Correct tag assignment:** Confirmed logs are categorized correctly based on the lookup table.
- **Output validation:** Verified that `output_results.txt` contains accurate summaries.

## Key Insights
- The parser **efficiently handles large log files** by processing them line by line.
- It dynamically resolves protocol names, ensuring **up-to-date protocol mapping**.
- The program is **built with error handling** to manage missing files, malformed data, and unexpected inputs gracefully.
- The modular design makes it **easy to extend and customize** for other log processing needs.

## Summary
The Flow Log Parser is a straightforward yet effective tool for analyzing AWS VPC flow logs. It categorizes logs, skips invalid data, and provides clear summaries of network activity. With robust testing and dynamic protocol handling, this tool is reliable, efficient, and easy to use!
