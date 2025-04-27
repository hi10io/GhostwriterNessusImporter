# GhostwriterNessusImporter

### Nessus to Ghostwriter Importer

This command-line tool is designed to simplify the process of importing Nessus scan results into Ghostwriter reports. By retrieving and parsing Nessus files, it enables automated report generation within Ghostwriter using its API.

## Features

- Parse Nessus files from the local filesystem, eliminate duplicates, sort by CVSS, and import findings into Ghostwriter report.

## Upcoming Features
- Retrieve Nessus scan files from a Nessus server

## Requirements

- Ghostwriter API access, including a valid report ID and API token or username and password.
- Nessus scan files stored locally

## Setup

Create and activate virtual environment:

```
python3 -m venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

## Basic Usage

### Importing Local Nessus Files to Ghostwriter
```bash
python nessus_importer.py --gw-report-id 123 --gw-api-token ABCDEF123 --gw-url https://ghostwriter.local/api --nessus-files file1.nessus file2.nessus
```

### Import and Merging All Nessus Files in Local Directory and Importing to Ghostwriter
```bash
python nessus_importer.py --gw-report-id 123 --gw-api-token ABCDEF123 --gw-url https://ghostwriter.local/api --nessus-dir nessus_files
```

### Excluding Specific Hosts from Parsing
```bash
python nessus_importer.py --gw-report-id 123 --gw-api-token ABCDEF123 --gw-url https://ghostwriter.local/api --nessus-files file1.nessus --exclude-hosts 192.168.1.1 192.168.1.2
```

### Coming Soon - Retrieving Nessus Files from a Server and Importing to Ghostwriter
```bash
python nessus_importer.py --gw-report-id 123 --gw-api-token ABCDEF123 --gw-url https://ghostwriter.local/api --nessus-url https://nessus.server.local --nessus-user admin --nessus-pass password --nessus-retrieve
```

## Command-Line Reference

To use the tool, invoke it via the command line with the appropriate options. Below are the key arguments you can use to configure the tool:

### Options

- `-h, --help`: Show this help message and exit.

### Debug Options

- `--print-settings`: Print the current settings and exit. Useful for confirming configurations before running the tool.

### Logging Options

- `--log-level LOGGING_LEVEL`: Set the log level (e.g., `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). Default is usually `INFO`.
- `--logfile LOGGING_LOG_FILE`: Set the path for logging output to a file.

### Ghostwriter Options

- `--gw-report-id GHOSTWRITER_REPORT_ID`: Set the Ghostwriter report ID to which Nessus data should be imported.
- `--gw-api-token GHOSTWRITER_API_TOKEN`: Set the API token for authenticating with the Ghostwriter instance.
- `--gw-url GHOSTWRITER_URL`: Set the Ghostwriter URL (e.g., `https://ghostwriter.local/api`).
- `--gw-throttle GHOSTWRITER_THROTTLE`: Optional. Set throttle time (in seconds) between consecutive requests to Ghostwriter to avoid overloading the server.

### Nessus Options

- `--nessus-url NESSUS_URL`: Set the URL of the Nessus server (if retrieving files directly from the server).
- `--nessus-user NESSUS_USERNAME`: Provide the Nessus server username.
- `--nessus-pass NESSUS_PASSWORD`: Provide the Nessus server password.
- `--nessus-retrieve`: Enable this flag to retrieve Nessus files from the server before parsing.
- `--nessus-files NESSUS_FILES [NESSUS_FILES ...]`: List of local Nessus files to parse. Can accept multiple file paths.
- `--nessus-dir NESSUS_DIRECTORY`: Specify a directory containing multiple Nessus files to parse.
- `--exclude-hosts NESSUS_EXCLUDE_HOSTS [NESSUS_EXCLUDE_HOSTS ...]`: List of hosts to exclude from parsing.


## License

This tool is licensed under the GNU AGPLv3

## Support

For issues or questions, please open an issue on the project's GitHub page.

---

This README provides a high-level overview of the tool's functionality, arguments, and example usage. Be sure to tailor the commands and settings to your environment.
