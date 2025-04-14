#!/bin/bash

# Check if .env file exists
if [ -f .env ]; then
    echo "Warning: .env file already exists. Do you want to overwrite it? (y/n)"
    read answer
    if [ "$answer" != "y" ]; then
        echo "Setup aborted."
        exit 1
    fi
fi

# Ask for Telegram bot token
echo "Please enter your Telegram bot token (obtained from @BotFather):"
read token

# Ask for admin ID (optional)
echo "Please enter your Telegram user ID for receiving logs (optional, press Enter to skip):"
read admin_id

# Create .env file
echo "TELEGRAM_BOT_TOKEN=$token" > .env
if [ -n "$admin_id" ]; then
    echo "ADMIN_ID=$admin_id" >> .env
    echo "Admin ID set to $admin_id for log forwarding."
fi
echo ".env file created successfully."

# Check if Go is installed
if command -v go &> /dev/null; then
    echo "Go is installed. Building the bot..."
    go mod download
    go build
    echo "Bot built successfully. You can now run it with:"
    echo "./telegram-channel-discussion-defender"
else
    echo "Go is not installed. Do you want to use Docker instead? (y/n)"
    read answer
    if [ "$answer" == "y" ]; then
        # Check if Docker is installed
        if command -v docker &> /dev/null && command -v docker-compose &> /dev/null; then
            echo "Docker and Docker Compose are installed. Building and starting the bot..."
            docker-compose up -d
            echo "Bot started successfully. You can view logs with:"
            echo "docker-compose logs -f"
        else
            echo "Docker or Docker Compose is not installed. Please install them first."
            exit 1
        fi
    else
        echo "Please install Go and run this script again, or use Docker."
        exit 1
    fi
fi

echo ""
echo "Setup completed. Don't forget to add the bot to your group as an administrator with the following permissions:"
echo "- Delete messages"
echo "- Ban users"
echo "- Restrict users"
