#!/bin/bash

# PhantomFuzzer Installation Script
# This script builds the Docker image and creates a wrapper script for the phantomfuzzer command

# Exit on error
set -e

# Function to handle errors
handle_error() {
    echo "\nERROR: Installation failed at line $1"
    echo "Please check the error messages above and try again."
    exit 1
}

# Set up error handling
trap 'handle_error $LINENO' ERR

# Parse command line arguments
SKIP_DOCKER_BUILD=false
for arg in "$@"; do
    case $arg in
        --skip-docker-build)
            SKIP_DOCKER_BUILD=true
            shift
            ;;
        *)
            # Unknown option
            ;;
    esac
done

echo "===== PhantomFuzzer Installation ====="
echo "This script will install PhantomFuzzer and its dependencies."

# Set Docker Compose availability flag
DOCKER_COMPOSE_AVAILABLE=false
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE_AVAILABLE=true
fi

# Check if docker is installed
if command -v docker &> /dev/null; then
    echo "Docker is installed."
    
    # Check if we should skip Docker build
    if [ "$SKIP_DOCKER_BUILD" = true ]; then
        echo "Skipping Docker build as requested with --skip-docker-build option."
    else
        echo "Checking for Docker image..."
        
        # Check if the Docker image already exists
        if docker images -q phantomfuzzer &> /dev/null; then
            echo "PhantomFuzzer Docker image already exists. Skipping build."
        else
            echo "Building Docker image..."
            
            # Check if docker-compose is available
            if [ "$DOCKER_COMPOSE_AVAILABLE" = true ]; then
                echo "Using Docker Compose for build..."
                
                # Build using docker-compose
                docker-compose build phantomfuzzer
                
                if [ $? -ne 0 ]; then
                    echo "Error: Docker Compose build failed. Falling back to standard Docker build..."
                    echo "Building Docker image..."
                    
                    # Fallback to standard Docker build
                    docker build -t phantomfuzzer .
                    
                    if [ $? -ne 0 ]; then
                        echo "Error: Docker build failed. Please check your Docker installation and try again."
                        exit 1
                    fi
                fi
            else
                echo "Docker Compose not found. Using standard Docker build..."
                echo "Building Docker image..."
                
                # Build the Docker image
                docker build -t phantomfuzzer .
                
                if [ $? -ne 0 ]; then
                    echo "Error: Docker build failed. Please check your Docker installation and try again."
                    exit 1
                fi
            fi
            
            echo "Docker image built successfully."
        fi
    fi
else
    echo "Docker is not installed. Please install Docker to use PhantomFuzzer."
    exit 1
fi
echo "Creating wrapper script..."

# Create the wrapper script
WRAPPER_PATH="/usr/local/bin/phantomfuzzer"

# Create ASCII banner file if it doesn't exist
if [ ! -f "$(pwd)/ascii.txt" ]; then
    echo "Creating ASCII banner file..."
    cat > "$(pwd)/ascii.txt" << 'EOF'
██████╗░██╗░░██╗░█████╗░███╗░░██╗████████╗░█████╗░███╗░░░███╗
██╔══██╗██║░░██║██╔══██╗████╗░██║╚══██╔══╝██╔══██╗████╗░████║
██████╔╝███████║███████║██╔██╗██║░░░██║░░░██║░░██║██╔████╔██║
██╔═══╝░██╔══██║██╔══██║██║╚████║░░░██║░░░██║░░██║██║╚██╔╝██║
██║░░░░░██║░░██║██║░░██║██║░╚███║░░░██║░░░╚█████╔╝██║░╚═╝░██║
╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝░░░╚═╝░░░░╚════╝░╚═╝░░░░░╚═╝
EOF
fi

# Use the existing wrapper script
if [ ! -f "phantomfuzzer_wrapper.sh" ]; then
    echo "ERROR: phantomfuzzer_wrapper.sh not found in the current directory."
    echo "Please make sure you are running this script from the PhantomFuzzer directory."
    exit 1
fi

# Store the absolute path to the PhantomFuzzer directory
PHANTOM_DIR="$(pwd)"

# Create a temporary copy of the wrapper script with the correct PHANTOM_DIR
cp phantomfuzzer_wrapper.sh wrapper_script.tmp

# Check if PHANTOM_DIR is already defined in the script
if grep -q "PHANTOM_DIR=" wrapper_script.tmp; then
    # Update the existing PHANTOM_DIR in the wrapper script
    sed -i "s|PHANTOM_DIR=\".*\"|PHANTOM_DIR=\"$PHANTOM_DIR\"|g" wrapper_script.tmp
else
    # Add PHANTOM_DIR definition after the script header comments
    sed -i "/^# This script forwards/a\\\n# Path to PhantomFuzzer installation directory\nPHANTOM_DIR=\"$PHANTOM_DIR\"" wrapper_script.tmp
fi

# Read the wrapper script content
WRAPPER_CONTENT=$(cat wrapper_script.tmp)

# Clean up
rm wrapper_script.tmp

# Create the wrapper script with sudo
echo "\n===== Installing PhantomFuzzer Command ====="
echo "This will install the phantomfuzzer command in $WRAPPER_PATH"
echo "Please enter your password when prompted:"

# Explicitly ask for sudo password to ensure we have proper permissions
sudo -v

# Create the directory and install the wrapper script
echo "Creating directory and installing wrapper script..."
sudo mkdir -p /usr/local/bin

# Check if the target is a dangling symlink and remove it if it is
if [ -L "$WRAPPER_PATH" ] && [ ! -e "$WRAPPER_PATH" ]; then
    echo "Removing dangling symlink at $WRAPPER_PATH"
    sudo rm -f "$WRAPPER_PATH"
fi

# If the file exists (regular file or valid symlink), remove it to avoid conflicts
if [ -e "$WRAPPER_PATH" ]; then
    echo "Removing existing file at $WRAPPER_PATH"
    sudo rm -f "$WRAPPER_PATH"
fi

# Write the wrapper script to a temporary file and then move it with sudo
echo "$WRAPPER_CONTENT" > wrapper_script_final.tmp

# Make sure the temporary file was created successfully
if [ ! -f wrapper_script_final.tmp ]; then
    echo "ERROR: Failed to create temporary wrapper script file"
    exit 1
fi

# Copy the file to the destination with sudo
sudo cp wrapper_script_final.tmp $WRAPPER_PATH

# Verify the file was copied successfully
if [ ! -f "$WRAPPER_PATH" ]; then
    echo "ERROR: Failed to copy wrapper script to $WRAPPER_PATH"
    rm -f wrapper_script_final.tmp
    exit 1
fi

# Set executable permissions
sudo chmod +x $WRAPPER_PATH

# Clean up the temporary file
rm -f wrapper_script_final.tmp

echo "Wrapper script installed successfully in $WRAPPER_PATH"

# Set installation success flag
INSTALLATION_SUCCESS=true

# Install man page if available
if [ -f "phantomfuzzer.1" ]; then
    echo "\n===== Installing Man Page ====="
    echo "This will install the PhantomFuzzer man page for system-wide access"
    
    # We already have sudo access from earlier, so proceed with installation
    echo "Creating man directory and installing man page..."
    sudo mkdir -p /usr/local/share/man/man1
    sudo cp phantomfuzzer.1 /usr/local/share/man/man1/
    
    MAN_INSTALLED=true
    
    # Check if mandb command exists and update the man database
    if command -v mandb &> /dev/null; then
        echo "Updating man database..."
        sudo mandb > /dev/null 2>&1
        echo "Man database updated successfully."
    else
        echo "Note: 'mandb' command not found. Man page is installed but the database could not be updated."
        echo "You may need to manually update your man database or install the 'man-db' package."
    fi
    
    echo "Man page installed successfully. You can access it with:"
    echo "  man phantomfuzzer"
    echo "\nAlternatively, you can view the manual with:"
    echo "  phantomfuzzer man"
fi

# Check if Docker image was built successfully
if ! docker image inspect phantomfuzzer:latest > /dev/null 2>&1; then
    echo "\n===== Installation Error ====="
    echo "ERROR: Docker image build failed."
    echo "Please check the Docker error messages above."
    exit 1
fi

# Final verification
if [ ! -f "$WRAPPER_PATH" ]; then
    echo "\n===== Installation Error ====="
    echo "ERROR: Wrapper script was not installed correctly."
    echo "Please check the error messages above."
    exit 1
fi

# Success message
echo "\n===== Installation Complete ====="
echo "PhantomFuzzer has been successfully installed!"
echo ""
echo "You can now use PhantomFuzzer by running:"
echo "  phantomfuzzer [command]"
echo ""
echo "Examples:"
echo "  phantomfuzzer --help                           # Show help information"
echo "  phantomfuzzer scanner web --url example.com    # Scan a website"
echo "  phantomfuzzer fuzzer api --spec api-spec.yaml  # Fuzz an API"
echo "  phantomfuzzer man                             # View the manual"
echo ""
echo "Documentation:"
echo "  man phantomfuzzer                             # View the man page"
echo "  phantomfuzzer --help                           # Show command help"
echo ""
echo "For more information, visit: https://github.com/ghostsecurity420/PhantomFuzzer"
echo ""
