#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

# Get the current directory
CURRENT_DIR=$(pwd)
CURRENT_USER=$(logname || whoami)

echo "Installing Telegram Bot as a systemd service..."
echo "Current directory: $CURRENT_DIR"
echo "Current user: $CURRENT_USER"

# Create a temporary file with the correct paths
cat > telegram-bot.service.tmp << EOL
[Unit]
Description=Telegram Channel Discussion Defender
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/telegram-channel-discussion-defender
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOL

# Copy the service file to systemd directory
cp telegram-bot.service.tmp /etc/systemd/system/telegram-bot.service
rm telegram-bot.service.tmp

# Reload systemd
systemctl daemon-reload

echo "Service installed. You can now start it with:"
echo "sudo systemctl start telegram-bot.service"
echo ""
echo "To enable it to start on boot:"
echo "sudo systemctl enable telegram-bot.service"
echo ""
echo "To check the status:"
echo "sudo systemctl status telegram-bot.service"
echo ""
echo "To view logs:"
echo "sudo journalctl -u telegram-bot.service -f"
