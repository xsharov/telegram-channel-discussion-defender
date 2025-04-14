package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/joho/godotenv"
	tb "gopkg.in/telebot.v3"
)

// Config holds the bot configuration
type Config struct {
	MuteDurationNonLatinCyrillic time.Duration // 5 minutes default
	MuteDurationShortMessage     time.Duration // 1 minute default
	MuteDurationSuspiciousName   time.Duration // 1 day default
	MuteDurationAntiRaid         time.Duration // 1 hour default
	AntiRaidMessagesThreshold    int           // 10 messages default
	AntiRaidTimeWindow           time.Duration // 5 seconds default
	Whitelist                    map[string]bool
	AntiRaidMode                 bool
	AdminID                      int64 // Admin ID to receive logs
	mutex                        sync.RWMutex
}

// MessageCounter for anti-raid detection
type MessageCounter struct {
	messages []time.Time
	mutex    sync.Mutex
}

var (
	config         Config
	messageCounter MessageCounter
	bot            *tb.Bot
)

// logf sends a log message to both the console and the admin (if configured)
func logf(format string, args ...interface{}) {
	// Log to console
	log.Printf(format, args...)

	// Log to admin if configured
	config.mutex.RLock()
	adminID := config.AdminID
	config.mutex.RUnlock()

	if adminID > 0 && bot != nil {
		admin := &tb.User{ID: adminID}
		message := fmt.Sprintf(format, args...)
		_, err := bot.Send(admin, message)
		if err != nil {
			log.Printf("Error sending log to admin: %v", err)
		}
	}
}

func init() {
	// Initialize default configuration
	config = Config{
		MuteDurationNonLatinCyrillic: 5 * time.Minute,
		MuteDurationShortMessage:     1 * time.Minute,
		MuteDurationSuspiciousName:   24 * time.Hour,
		MuteDurationAntiRaid:         1 * time.Hour,
		AntiRaidMessagesThreshold:    10,
		AntiRaidTimeWindow:           5 * time.Second,
		Whitelist:                    make(map[string]bool),
		AntiRaidMode:                 false,
	}

	messageCounter = MessageCounter{
		messages: make([]time.Time, 0, 100),
	}

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load admin ID from environment variables
	if adminIDStr := os.Getenv("ADMIN_ID"); adminIDStr != "" {
		if adminID, err := strconv.ParseInt(adminIDStr, 10, 64); err == nil {
			config.AdminID = adminID
			log.Printf("Admin ID loaded from environment: %d", adminID)
		} else {
			log.Printf("Invalid ADMIN_ID in environment: %v", err)
		}
	}
}

func main() {
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		log.Fatal("TELEGRAM_BOT_TOKEN environment variable is not set")
	}

	// Create a new bot
	var err error
	bot, err = tb.NewBot(tb.Settings{
		Token:  token,
		Poller: &tb.LongPoller{Timeout: 10 * time.Second},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Set the global bot variable for logging
	b := bot

	// Handle messages
	b.Handle(tb.OnText, func(c tb.Context) error {
		return handleMessage(b, c)
	})

	// Handle stickers
	b.Handle(tb.OnSticker, func(c tb.Context) error {
		return handleMessage(b, c)
	})

	// Handle admin commands
	b.Handle("/config", func(c tb.Context) error {
		return handleConfigCommand(b, c)
	})

	b.Handle("/whitelist_add", func(c tb.Context) error {
		return handleWhitelistAddCommand(b, c)
	})

	b.Handle("/whitelist_remove", func(c tb.Context) error {
		return handleWhitelistRemoveCommand(b, c)
	})

	b.Handle("/whitelist_list", func(c tb.Context) error {
		return handleWhitelistListCommand(b, c)
	})

	b.Handle("/set_mute_non_latin_cyrillic", func(c tb.Context) error {
		return handleSetMuteDurationCommand(b, c, "non_latin_cyrillic")
	})

	b.Handle("/set_mute_short_message", func(c tb.Context) error {
		return handleSetMuteDurationCommand(b, c, "short_message")
	})

	b.Handle("/set_mute_suspicious_name", func(c tb.Context) error {
		return handleSetMuteDurationCommand(b, c, "suspicious_name")
	})

	b.Handle("/set_mute_anti_raid", func(c tb.Context) error {
		return handleSetMuteDurationCommand(b, c, "anti_raid")
	})

	b.Handle("/set_anti_raid_threshold", func(c tb.Context) error {
		return handleSetAntiRaidThresholdCommand(b, c)
	})

	b.Handle("/set_anti_raid_window", func(c tb.Context) error {
		return handleSetAntiRaidWindowCommand(b, c)
	})

	b.Handle("/set_admin_id", func(c tb.Context) error {
		return handleSetAdminIDCommand(b, c)
	})

	logf("Bot started")
	b.Start()
}

// handleMessage processes incoming messages and applies moderation rules
func handleMessage(b *tb.Bot, c tb.Context) error {
	msg := c.Message()
	sender := msg.Sender
	chat := msg.Chat

	// Skip processing for private chats
	if chat.Type == tb.ChatPrivate {
		return nil
	}

	// Check if user is in whitelist
	config.mutex.RLock()
	isWhitelisted := config.Whitelist[sender.Username]
	config.mutex.RUnlock()

	if isWhitelisted {
		return nil
	}

	// Check if user is an admin
	chatMember, err := b.ChatMemberOf(chat, sender)
	if err != nil {
		logf("Error checking if user is admin: %v", err)
		return nil
	}

	isAdmin := chatMember.Role == tb.Administrator || chatMember.Role == tb.Creator
	if isAdmin {
		// Update message counter for anti-raid detection
		updateMessageCounter()
		return nil
	}

	// Check if anti-raid mode is active
	config.mutex.RLock()
	antiRaidMode := config.AntiRaidMode
	config.mutex.RUnlock()

	if antiRaidMode {
		// Mute user in anti-raid mode
		config.mutex.RLock()
		muteDuration := config.MuteDurationAntiRaid
		config.mutex.RUnlock()

		muteUser(b, chat, sender, muteDuration)
		deleteMessage(b, msg)
		return nil
	}

	// Check if anti-raid should be activated
	if shouldActivateAntiRaid() {
		logf("Activating anti-raid mode")
		config.mutex.Lock()
		config.AntiRaidMode = true
		config.mutex.Unlock()

		// Start a goroutine to deactivate anti-raid mode after some time
		go func() {
			time.Sleep(5 * time.Minute) // Deactivate after 5 minutes
			config.mutex.Lock()
			config.AntiRaidMode = false
			config.mutex.Unlock()
			logf("Deactivated anti-raid mode")
		}()
	}

	// Update message counter for anti-raid detection
	updateMessageCounter()

	// Check if user is a member of the group
	isMember := chatMember.Role == tb.Member

	// Check username for suspicious pattern (ends with 5+ digits)
	if hasSuspiciousUsername(sender.Username) {
		config.mutex.RLock()
		muteDuration := config.MuteDurationSuspiciousName
		config.mutex.RUnlock()

		muteUser(b, chat, sender, muteDuration)
		deleteMessage(b, msg)
		return nil
	}

	// Check message content
	text := msg.Text
	if msg.Sticker != nil {
		text = msg.Sticker.Emoji
	}

	// Check for short messages (5 or fewer characters)
	if len(text) <= 5 && text != "" {
		config.mutex.RLock()
		muteDuration := config.MuteDurationShortMessage
		config.mutex.RUnlock()

		muteUser(b, chat, sender, muteDuration)
		deleteMessage(b, msg)
		return nil
	}

	// Check for non-Latin and non-Cyrillic characters
	if !isMember && containsNonLatinCyrillic(text) {
		config.mutex.RLock()
		muteDuration := config.MuteDurationNonLatinCyrillic
		config.mutex.RUnlock()

		muteUser(b, chat, sender, muteDuration)
		deleteMessage(b, msg)
		return nil
	}

	return nil
}

// containsNonLatinCyrillic checks if the text contains characters outside Latin and Cyrillic alphabets
func containsNonLatinCyrillic(text string) bool {
	for _, r := range text {
		// Skip spaces and common punctuation
		if unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsDigit(r) {
			continue
		}

		// Check if character is Latin or Cyrillic
		if !(unicode.Is(unicode.Latin, r) || unicode.Is(unicode.Cyrillic, r)) {
			return true
		}
	}
	return false
}

// hasSuspiciousUsername checks if username ends with 5+ digits
func hasSuspiciousUsername(username string) bool {
	if username == "" {
		return false
	}

	re := regexp.MustCompile(`\d{5,}$`)
	return re.MatchString(username)
}

// updateMessageCounter adds current time to message counter
func updateMessageCounter() {
	now := time.Now()
	messageCounter.mutex.Lock()
	defer messageCounter.mutex.Unlock()

	// Add current message time
	messageCounter.messages = append(messageCounter.messages, now)

	// Remove old messages outside the time window
	config.mutex.RLock()
	timeWindow := config.AntiRaidTimeWindow
	config.mutex.RUnlock()

	cutoffTime := now.Add(-timeWindow)
	i := 0
	for i < len(messageCounter.messages) && messageCounter.messages[i].Before(cutoffTime) {
		i++
	}

	if i > 0 {
		messageCounter.messages = messageCounter.messages[i:]
	}
}

// shouldActivateAntiRaid checks if anti-raid mode should be activated
func shouldActivateAntiRaid() bool {
	messageCounter.mutex.Lock()
	defer messageCounter.mutex.Unlock()

	config.mutex.RLock()
	threshold := config.AntiRaidMessagesThreshold
	timeWindow := config.AntiRaidTimeWindow
	config.mutex.RUnlock()

	// Count messages within time window
	now := time.Now()
	cutoffTime := now.Add(-timeWindow)

	recentMessages := 0
	for i := len(messageCounter.messages) - 1; i >= 0; i-- {
		if messageCounter.messages[i].After(cutoffTime) {
			recentMessages++
		} else {
			break
		}
	}

	return recentMessages >= threshold
}

// muteUser restricts a user from sending messages for the specified duration
func muteUser(b *tb.Bot, chat *tb.Chat, user *tb.User, duration time.Duration) {
	until := time.Now().Add(duration)

	member := &tb.ChatMember{
		User:            user,
		RestrictedUntil: until.Unix(),
		Rights: tb.Rights{
			CanSendMessages: false,
			CanSendMedia:    false,
			CanSendPolls:    false,
			CanSendOther:    false,
			CanAddPreviews:  false,
		},
	}

	err := b.Restrict(chat, member)
	if err != nil {
		logf("Error muting user %s: %v", user.Username, err)
	} else {
		logf("Muted user %s for %v", user.Username, duration)
	}
}

// deleteMessage deletes a message
func deleteMessage(b *tb.Bot, msg *tb.Message) {
	err := b.Delete(msg)
	if err != nil {
		logf("Error deleting message: %v", err)
	}
}

// Admin command handlers

// handleConfigCommand shows current configuration
func handleConfigCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	config.mutex.RLock()
	adminID := config.AdminID
	defer config.mutex.RUnlock()

	configText := fmt.Sprintf(
		"*Current Configuration:*\n"+
			"- Mute duration for non-Latin/Cyrillic: %v\n"+
			"- Mute duration for short messages: %v\n"+
			"- Mute duration for suspicious usernames: %v\n"+
			"- Mute duration in anti-raid mode: %v\n"+
			"- Anti-raid messages threshold: %d\n"+
			"- Anti-raid time window: %v\n"+
			"- Anti-raid mode active: %v\n"+
			"- Admin ID for logs: %d\n\n"+
			"Use the following commands to configure:\n"+
			"/whitelist_add @username\n"+
			"/whitelist_remove @username\n"+
			"/whitelist_list\n"+
			"/set_mute_non_latin_cyrillic [minutes]\n"+
			"/set_mute_short_message [minutes]\n"+
			"/set_mute_suspicious_name [hours]\n"+
			"/set_mute_anti_raid [hours]\n"+
			"/set_anti_raid_threshold [count]\n"+
			"/set_anti_raid_window [seconds]\n"+
			"/set_admin_id [telegram_id]",
		config.MuteDurationNonLatinCyrillic,
		config.MuteDurationShortMessage,
		config.MuteDurationSuspiciousName,
		config.MuteDurationAntiRaid,
		config.AntiRaidMessagesThreshold,
		config.AntiRaidTimeWindow,
		config.AntiRaidMode,
		adminID,
	)

	_, err := b.Send(c.Message().Chat, configText, &tb.SendOptions{
		ParseMode: tb.ModeMarkdown,
	})
	return err
}

// handleWhitelistAddCommand adds a user to the whitelist
func handleWhitelistAddCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		_, err := b.Send(c.Message().Chat, "Usage: /whitelist_add @username")
		return err
	}

	username := strings.TrimPrefix(args[1], "@")

	config.mutex.Lock()
	config.Whitelist[username] = true
	config.mutex.Unlock()

	_, err := b.Send(c.Message().Chat, fmt.Sprintf("Added @%s to whitelist", username))
	logf("Admin %s added @%s to whitelist", c.Message().Sender.Username, username)
	return err
}

// handleWhitelistRemoveCommand removes a user from the whitelist
func handleWhitelistRemoveCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		_, err := b.Send(c.Message().Chat, "Usage: /whitelist_remove @username")
		return err
	}

	username := strings.TrimPrefix(args[1], "@")

	config.mutex.Lock()
	delete(config.Whitelist, username)
	config.mutex.Unlock()

	_, err := b.Send(c.Message().Chat, fmt.Sprintf("Removed @%s from whitelist", username))
	logf("Admin %s removed @%s from whitelist", c.Message().Sender.Username, username)
	return err
}

// handleWhitelistListCommand lists all whitelisted users
func handleWhitelistListCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	config.mutex.RLock()
	defer config.mutex.RUnlock()

	var whitelistText string
	if len(config.Whitelist) == 0 {
		whitelistText = "Whitelist is empty"
	} else {
		whitelistText = "*Whitelisted users:*\n"
		for username := range config.Whitelist {
			whitelistText += fmt.Sprintf("- @%s\n", username)
		}
	}

	_, err := b.Send(c.Message().Chat, whitelistText, &tb.SendOptions{
		ParseMode: tb.ModeMarkdown,
	})
	return err
}

// handleSetMuteDurationCommand sets mute duration for different violation types
func handleSetMuteDurationCommand(b *tb.Bot, c tb.Context, violationType string) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		var usage string
		switch violationType {
		case "non_latin_cyrillic":
			usage = "Usage: /set_mute_non_latin_cyrillic [minutes]"
		case "short_message":
			usage = "Usage: /set_mute_short_message [minutes]"
		case "suspicious_name":
			usage = "Usage: /set_mute_suspicious_name [hours]"
		case "anti_raid":
			usage = "Usage: /set_mute_anti_raid [hours]"
		}
		_, err := b.Send(c.Message().Chat, usage)
		return err
	}

	var duration time.Duration
	var err error
	var unit string

	switch violationType {
	case "non_latin_cyrillic", "short_message":
		minutes := 0
		_, err = fmt.Sscanf(args[1], "%d", &minutes)
		duration = time.Duration(minutes) * time.Minute
		unit = "minutes"
	case "suspicious_name", "anti_raid":
		hours := 0
		_, err = fmt.Sscanf(args[1], "%d", &hours)
		duration = time.Duration(hours) * time.Hour
		unit = "hours"
	}

	if err != nil {
		_, err = b.Send(c.Message().Chat, "Invalid duration. Please provide a number.")
		return err
	}

	config.mutex.Lock()
	switch violationType {
	case "non_latin_cyrillic":
		config.MuteDurationNonLatinCyrillic = duration
	case "short_message":
		config.MuteDurationShortMessage = duration
	case "suspicious_name":
		config.MuteDurationSuspiciousName = duration
	case "anti_raid":
		config.MuteDurationAntiRaid = duration
	}
	config.mutex.Unlock()

	_, err = b.Send(c.Message().Chat, fmt.Sprintf("Mute duration for %s set to %v %s",
		violationType, duration.Minutes(), unit))
	logf("Admin %s set mute duration for %s to %v %s", c.Message().Sender.Username, violationType, duration.Minutes(), unit)
	return err
}

// handleSetAntiRaidThresholdCommand sets the threshold for anti-raid activation
func handleSetAntiRaidThresholdCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		_, err := b.Send(c.Message().Chat, "Usage: /set_anti_raid_threshold [count]")
		return err
	}

	threshold := 0
	_, err := fmt.Sscanf(args[1], "%d", &threshold)
	if err != nil || threshold < 1 {
		_, err = b.Send(c.Message().Chat, "Invalid threshold. Please provide a positive number.")
		return err
	}

	config.mutex.Lock()
	config.AntiRaidMessagesThreshold = threshold
	config.mutex.Unlock()

	_, err = b.Send(c.Message().Chat, fmt.Sprintf("Anti-raid threshold set to %d messages", threshold))
	logf("Admin %s set anti-raid threshold to %d messages", c.Message().Sender.Username, threshold)
	return err
}

// handleSetAntiRaidWindowCommand sets the time window for anti-raid detection
func handleSetAntiRaidWindowCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		_, err := b.Send(c.Message().Chat, "Usage: /set_anti_raid_window [seconds]")
		return err
	}

	seconds := 0
	_, err := fmt.Sscanf(args[1], "%d", &seconds)
	if err != nil || seconds < 1 {
		_, err = b.Send(c.Message().Chat, "Invalid time window. Please provide a positive number of seconds.")
		return err
	}

	config.mutex.Lock()
	config.AntiRaidTimeWindow = time.Duration(seconds) * time.Second
	config.mutex.Unlock()

	_, err = b.Send(c.Message().Chat, fmt.Sprintf("Anti-raid time window set to %d seconds", seconds))
	logf("Admin %s set anti-raid time window to %d seconds", c.Message().Sender.Username, seconds)
	return err
}

// handleSetAdminIDCommand sets the admin ID for receiving logs
func handleSetAdminIDCommand(b *tb.Bot, c tb.Context) error {
	// Check if user is an admin
	if !isAdmin(b, c) {
		return nil
	}

	args := strings.Fields(c.Message().Text)
	if len(args) < 2 {
		_, err := b.Send(c.Message().Chat, "Usage: /set_admin_id [telegram_id]")
		return err
	}

	adminID := int64(0)
	_, err := fmt.Sscanf(args[1], "%d", &adminID)
	if err != nil || adminID <= 0 {
		_, err = b.Send(c.Message().Chat, "Invalid admin ID. Please provide a valid Telegram user ID (a positive number).")
		return err
	}

	config.mutex.Lock()
	config.AdminID = adminID
	config.mutex.Unlock()

	_, err = b.Send(c.Message().Chat, fmt.Sprintf("Admin ID set to %d. This user will now receive log messages.", adminID))
	logf("Admin %s set log recipient to user ID %d", c.Message().Sender.Username, adminID)

	// Send a test message to the admin
	admin := &tb.User{ID: adminID}
	_, err = b.Send(admin, "You have been set as the admin for log messages. You will now receive log notifications from the bot.")
	if err != nil {
		_, err = b.Send(c.Message().Chat, fmt.Sprintf("Warning: Could not send a test message to the admin: %v", err))
	}

	return err
}

// isAdmin checks if the user is an admin of the chat
func isAdmin(b *tb.Bot, c tb.Context) bool {
	msg := c.Message()
	sender := msg.Sender
	chat := msg.Chat

	chatMember, err := b.ChatMemberOf(chat, sender)
	if err != nil {
		logf("Error checking if user is admin: %v", err)
		return false
	}

	isAdmin := chatMember.Role == tb.Administrator || chatMember.Role == tb.Creator
	if !isAdmin {
		_, err = b.Send(chat, "This command is only available to administrators")
		if err != nil {
			logf("Error sending admin-only message: %v", err)
		}
	}

	return isAdmin
}
