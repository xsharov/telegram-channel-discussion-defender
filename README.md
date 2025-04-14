# Telegram Channel Discussion Bot

A moderation bot for Telegram groups that helps maintain order by automatically muting users based on specific rules.

## Features

- Mutes users (not in the group) for 5 minutes if they use non-Latin or non-Cyrillic characters
- Mutes users for 1 minute if their message is 5 or fewer characters (including stickers, emojis, symbols)
- Ignores images and other attachments
- Anti-raid mode: if 10 messages are sent within 5 seconds, mutes all non-admin users who try to write for 1 hour
- Mutes users for 1 day if their username ends with at least 5 digits
- Deletes all messages that violate these rules
- Whitelist for users who are exempt from these rules
- Admin commands to configure mute durations and other settings

## Setup

### Quick Setup (Recommended)

1. Create a new bot using [@BotFather](https://t.me/BotFather) on Telegram and get the token
2. Run the setup script and follow the instructions:
   ```
   ./setup.sh
   ```
   The script will guide you through the setup process and automatically detect if you have Go or Docker installed.

### Manual Setup with Go

1. Create a new bot using [@BotFather](https://t.me/BotFather) on Telegram and get the token
2. Copy `.env.example` to `.env` and add your bot token:
   ```
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
   ```
3. Make sure you have Go installed (version 1.16 or higher recommended)
4. Install dependencies:
   ```
   go mod download
   ```
5. Build and run the bot:
   ```
   go build
   ./telegram-chanel-discussion-bot
   ```

### Manual Setup with Docker

1. Create a new bot using [@BotFather](https://t.me/BotFather) on Telegram and get the token
2. Copy `.env.example` to `.env` and add your bot token:
   ```
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token_here
   ```
3. Make sure you have Docker and Docker Compose installed
4. Build and run the bot:
   ```
   docker-compose up -d
   ```
5. To view logs:
   ```
   docker-compose logs -f
   ```

### Running as a Systemd Service (Linux)

#### Automatic Installation (Recommended)

1. Make sure you have built the bot using the Go setup method
2. Run the installation script:
   ```
   sudo ./install-service.sh
   ```
3. Start the service:
   ```
   sudo systemctl start telegram-bot.service
   ```
4. Enable the service to start on boot:
   ```
   sudo systemctl enable telegram-bot.service
   ```

#### Manual Installation

1. Edit the `telegram-bot.service` file and update the `User`, `WorkingDirectory`, and `ExecStart` paths to match your system
2. Copy the service file to the systemd directory:
   ```
   sudo cp telegram-bot.service /etc/systemd/system/
   ```
3. Reload systemd:
   ```
   sudo systemctl daemon-reload
   ```
4. Enable and start the service:
   ```
   sudo systemctl enable telegram-bot.service
   sudo systemctl start telegram-bot.service
   ```
5. Check the status:
   ```
   sudo systemctl status telegram-bot.service
   ```
6. View logs:
   ```
   sudo journalctl -u telegram-bot.service -f
   ```

## Admin Commands

- `/config` - Show current configuration
- `/whitelist_add @username` - Add a user to the whitelist
- `/whitelist_remove @username` - Remove a user from the whitelist
- `/whitelist_list` - List all whitelisted users
- `/set_mute_non_latin_cyrillic [minutes]` - Set mute duration for non-Latin/Cyrillic messages
- `/set_mute_short_message [minutes]` - Set mute duration for short messages
- `/set_mute_suspicious_name [hours]` - Set mute duration for users with suspicious usernames
- `/set_mute_anti_raid [hours]` - Set mute duration for anti-raid mode
- `/set_anti_raid_threshold [count]` - Set message count threshold for anti-raid activation
- `/set_anti_raid_window [seconds]` - Set time window for anti-raid detection

## Bot Permissions

For the bot to work properly, it needs to be added to the group as an administrator with the following permissions:
- Delete messages
- Ban users
- Restrict users

## License

MIT
