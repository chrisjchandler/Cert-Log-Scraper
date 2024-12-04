# CertStream Monitor Tool

## Overview
This tool connects to CertStream, a real-time feed of newly issued SSL/TLS certificates, and monitors for any new certificates that match domain names in the specified zones. The tool captures and logs relevant certificate information and writes any matches to an output file for further review and analysis.

## How It Works
1. **Load Zones**: The tool first loads a list of domains/zones from a `zones.json` file. These domains represent the zones that and require monitoring.

2. **Connect to CertStream**: The tool connects to CertStream, a real-time feed of new SSL/TLS certificates, to receive a continuous stream of certificate updates.

3. **Matching Certificates**: For each certificate update received, the tool checks if the certificate's domains match any of the managed zones.

4. **Logging Matches**: If a match is found, relevant certificate details are extracted and saved to an output file (`output.json`) for further inspection.

## Features
- **Real-Time Monitoring**: Connects to the CertStream API to receive and process certificate updates in real-time.
- **Domain Matching**: Matches new certificates against zones to detect potential rogue certificates.
- **Data Logging**: Captures information such as certificate issuer, validity period, and matching domains, which is then saved to `output.json`.
- **Automatic Reconnection**: Automatically reconnects to CertStream if the connection drops, ensuring continuous monitoring.

## Prerequisites
- **Go Environment**: Ensure that Go is installed and set up on your machine.
- **CertStream-Go**: This tool uses the [certstream-go](https://github.com/CaliDog/certstream-go) library, which can be installed via:
  ```sh
  go get github.com/CaliDog/certstream-go
  
ALT: 
"go mod init ctls.go" and "go mod tidy" to download the certstream library.
```

## Installation
1. Clone the repository or copy the source code to your desired location.
2. Install necessary dependencies by running:
   ```sh
   go get github.com/CaliDog/certstream-go
   ```

## Running the Tool
1. Ensure that your `zones.json` file contains the list of domains to be monitored. The file should have a format like:
   ```json
   [
       "foo.bar",
       "snazzydomain.org",
       "yetanotherdomain.net"
   ]
   ```
2. Run the tool:
   ```sh
   go run ctls.go
   ```
3. The tool will connect to CertStream and start monitoring for any certificates that match the domains specified in `zones.json`.

## Output
- **Output File**: All matching certificates are logged to `output.json`. The file will contain JSON entries for each match, including details like:
  - Certificate Index
  - All Domains on the Certificate
  - Certificate Link
  - Authority Info Access
  - Subject Alternative Name
  - Issuer Common Name
  - Validity Period (Not Before / Not After)
  - Log Source Details
  - Update Type

## Configuration
- **zones.json**: Modify this file to specify the domains/zones to be monitored.
- **output.json**: The output file where matching certificates are logged.
- **Verbose Logging**: Enable or disable verbose logging by modifying the `verboseLogging` flag in the source code.

## Known Issues
- **Connection Drops**: Occasionally, the connection to CertStream may drop unexpectedly. The tool will automatically attempt to reconnect after a brief delay.
- **Certificate Parsing**: Not all certificate data can be parsed if they do not follow the standard x509 format, leading to a message like "unrecognized certificate data format". This is expected behavior for some certificate types.

## License
This tool is distributed under the MIT License.

## Acknowledgments
- **CertStream**: Real-time certificate transparency monitoring feed used for tracking new certificates.
- **Certstream-Go**: Go client library for interacting with the CertStream API.

## Contribution
Feel free to open issues or pull requests to contribute to the project. Suggestions and improvements are always welcome!
