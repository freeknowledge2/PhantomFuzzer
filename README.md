# PhantomFuzzer

PhantomFuzzer is an advanced security testing toolkit that combines traditional fuzzing techniques with machine learning capabilities to detect vulnerabilities in web applications, APIs, protocols, and files.

## Features

- **Comprehensive Fuzzing**: Multiple fuzzer types for API, protocol, and input fuzzing
- **Advanced Scanning**: Web application, API, and file scanning capabilities
- **Payload Generation**: Extensive library of attack payloads for various vulnerability types
- **Machine Learning Integration**: Enhanced detection using ML algorithms (in development)
- **Extensible Architecture**: Modular design for easy extension with new capabilities

## Installation

### Prerequisites

- Docker (version 19.03 or higher)
- Git (for cloning the repository)
- Bash shell

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/ghostsec420/PhantomFuzzer.git
   cd PhantomFuzzer
   ```

2. Run the installation script:
   ```bash
   ./install.sh
   ```

   This script will:
   - Build the Docker image with all dependencies
   - Create a wrapper script that allows you to use the `phantomfuzzer` command
   - Set appropriate permissions

3. Verify the installation:
   ```bash
   phantomfuzzer --help
   ```

## Usage Guide

PhantomFuzzer has three main command groups:
- `scanner`: Run various types of scanners against targets
- `fuzzer`: Test applications for vulnerabilities by sending unexpected inputs
- `payload`: Generate attack payloads for security testing

### Global Options

PhantomFuzzer provides several global options to control output verbosity and formatting:

```bash
# Show minimal output (only critical messages and results)
phantomfuzzer --quiet [command]

# Show more detailed output
phantomfuzzer --verbose [command]

# Show all debug information
phantomfuzzer --debug [command]

# Disable colored output
phantomfuzzer --no-color [command]
```

You can combine these options as needed:

```bash
phantomfuzzer --verbose --no-color scanner web --url https://example.com
```

### Scanning Operations

#### Web Application Scanning

PhantomFuzzer allows you to scan web applications for vulnerabilities:

##### Basic Web Scanning

```bash
phantomfuzzer scanner web --url https://example.com
```

##### Scan with Authentication

```bash
phantomfuzzer scanner web --url https://example.com --auth '{"username":"user","password":"pass"}'
```

##### Control Scan Depth

```bash
phantomfuzzer scanner web --url https://example.com --depth 2
```

##### Save Results to a File

```bash
phantomfuzzer scanner web --url https://example.com --output web_results.json --format json
```

#### API Scanning

Scan your APIs for potential vulnerabilities:

```bash
phantomfuzzer scanner api --url https://api.example.com
```

##### With OpenAPI/Swagger Specification

```bash
phantomfuzzer scanner api --url https://api.example.com --spec openapi.json
```

##### With Authentication

```bash
phantomfuzzer scanner api --url https://api.example.com --auth '{"token":"your-api-token"}'
```

##### Save Results to a File

```bash
phantomfuzzer scanner api --url https://api.example.com --output api_results.json --format json
```

#### File Scanning

Scan files and directories for vulnerabilities:

##### Scan a Single File

```bash
phantomfuzzer scanner file --path ./target/file.php
```

##### Recursive Directory Scan

```bash
phantomfuzzer scanner file --path ./target --recursive
```

##### Scan with File Pattern Matching

```bash
phantomfuzzer scanner file --path ./target --recursive --pattern "*.php"
```

##### Enable Machine Learning Enhanced Detection

```bash
phantomfuzzer scanner file --path ./target --ml-enhanced
```

##### Save Results to a File

```bash
phantomfuzzer scanner file --path ./target --output file_results.json --format json
```

### Fuzzing Operations

#### API Fuzzing

PhantomFuzzer provides the ability to fuzz APIs by sending crafted requests. Here's how to perform API fuzzing:

##### Basic API Fuzzing

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --method GET
```

##### POST Request Fuzzing

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --method POST --data '{"username":"test"}'
```

##### Fuzz with Custom Headers

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --headers '{"Authorization":"Bearer token"}'
```

##### With Authentication

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --auth '{"username":"user","password":"pass"}'
```

##### Control Fuzzing Intensity

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --iterations 200 --delay 0.2 --timeout 10
```

##### Save Results to a File

```bash
phantomfuzzer fuzzer api --target https://api.example.com/v1/users --output results.json --format json
```

#### Protocol Fuzzing

You can fuzz different protocols like TCP, SSH, and FTP. Below are examples:

##### TCP Protocol Fuzzing

```bash
phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol tcp
```

##### SSH Protocol Fuzzing

```bash
phantomfuzzer fuzzer protocol --target example.com --port 22 --protocol ssh
```

##### FTP Protocol Fuzzing

```bash
phantomfuzzer fuzzer protocol --target example.com --port 21 --protocol ftp
```

##### Control Protocol Fuzzing Intensity

```bash
phantomfuzzer fuzzer protocol --target example.com --port 80 --protocol http --iterations 100 --delay 0.5 --timeout 15
```

#### Input Fuzzing

You can fuzz various types of inputs, including files, stdin, and command-line arguments.

##### File Input Fuzzing

```bash
phantomfuzzer fuzzer input --target ./target/application --input-type file
```

##### Command-Line Argument Fuzzing

```bash
phantomfuzzer fuzzer input --target ./target/application --input-type argument
```

##### Save Results to a File

```bash
phantomfuzzer fuzzer input --target ./target/application --input-type file --output input_results.json --output-format json
```

### Payload Generation

PhantomFuzzer allows you to generate different types of attack payloads for various categories. Here's how you can use it:

#### List Available Payload Categories

```bash
phantomfuzzer payload list
```

#### Generate Specific Payloads

##### SQL Injection (Basic)

```bash
phantomfuzzer payload generate --category sql_injection --subcategory basic
```

##### Generate Multiple XSS Payloads

```bash
phantomfuzzer payload generate --category xss --count 5 --output xss_payloads.txt
```

##### Generate Command Injection Payloads in JSON Format

```bash
phantomfuzzer payload generate --category command_injection --format json
```

#### Generate Random Payloads

```bash
phantomfuzzer payload random --count 3
```

### Advanced Usage

#### Combining Operations

You can chain multiple operations for more comprehensive testing:

```bash
# Generate payloads and use them for API fuzzing
phantomfuzzer payload generate --category sql_injection --output sql_payloads.txt
phantomfuzzer fuzzer api --target https://api.example.com/query --method POST --data @sql_payloads.txt

# Scan and then fuzz discovered endpoints
phantomfuzzer scanner api --url https://api.example.com --output discovered_apis.json
phantomfuzzer fuzzer api --target https://api.example.com/query --method POST --data @discovered_apis.json
```

#### Debug Mode

Enable debug logging for more detailed output:

```bash
phantomfuzzer --debug scanner web --url https://example.com
```

### Debug Mode

Enable debug logging for more detailed output:

```bash
phantomfuzzer --debug scanner web --url https://example.com
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.