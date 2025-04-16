package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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

const (
	configFile    = "config.json"
	whitelistFile = "whitelist.json"
)

// Config holds the bot configuration
type Config struct {
	MuteDurationNonLatinCyrillic time.Duration   `json:"mute_duration_non_latin_cyrillic"` // 5 minutes default
	MuteDurationShortMessage     time.Duration   `json:"mute_duration_short_message"`      // 1 minute default
	MuteDurationSuspiciousName   time.Duration   `json:"mute_duration_suspicious_name"`    // 1 day default
	MuteDurationAntiRaid         time.Duration   `json:"mute_duration_anti_raid"`          // 1 hour default
	AntiRaidMessagesThreshold    int             `json:"anti_raid_messages_threshold"`     // 10 messages default
	AntiRaidTimeWindow           time.Duration   `json:"anti_raid_time_window"`            // 5 seconds default
	Whitelist                    map[string]bool `json:"-"`                                // Managed separately in whitelist.json
	AntiRaidMode                 bool            `json:"-"`                                // Runtime state, not persisted
	AdminID                      int64           `json:"admin_id"`                         // Admin ID to receive logs
	mutex                        sync.RWMutex    `json:"-"`                                // Internal state, not persisted
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

// --- Persistence Functions ---

// loadConfig loads configuration from config.json
func loadConfig() (Config, error) {
	defaultConfig := Config{
		MuteDurationNonLatinCyrillic: 0 * time.Minute,
		MuteDurationShortMessage:     0 * time.Minute,
		MuteDurationSuspiciousName:   0 * time.Hour,
		MuteDurationAntiRaid:         5 * time.Minute,
		AntiRaidMessagesThreshold:    10,
		AntiRaidTimeWindow:           5 * time.Second,
		Whitelist:                    make(map[string]bool), // Initialize map
		AntiRaidMode:                 false,                 // Default runtime state
		AdminID:                      0,                     // Default admin ID
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file '%s' not found, using defaults and creating file.", configFile)
			// Save default config to create the file
			if saveErr := saveConfig(defaultConfig); saveErr != nil {
				log.Printf("Error creating default config file: %v", saveErr)
				// Return default config even if saving failed
				return defaultConfig, nil
			}
			return defaultConfig, nil
		}
		return defaultConfig, fmt.Errorf("error reading config file %s: %w", configFile, err)
	}

	var loadedConfig Config
	if err := json.Unmarshal(data, &loadedConfig); err != nil {
		log.Printf("Error unmarshalling config file %s: %v. Using defaults.", configFile, err)
		return defaultConfig, nil // Return default config on unmarshal error
	}

	// Ensure runtime fields are initialized correctly after loading
	loadedConfig.Whitelist = make(map[string]bool) // Whitelist loaded separately
	loadedConfig.AntiRaidMode = false              // Reset runtime state

	log.Printf("Config loaded from %s", configFile)
	return loadedConfig, nil
}

// saveConfig saves configuration to config.json
func saveConfig(cfg Config) error {
	config.mutex.RLock()
	defer config.mutex.RUnlock()

	// Create a copy for saving, excluding runtime fields
	configToSave := cfg
	configToSave.Whitelist = nil      // Don't save whitelist in config.json
	configToSave.AntiRaidMode = false // Don't save runtime state

	data, err := json.MarshalIndent(configToSave, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}

	err = ioutil.WriteFile(configFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing config file %s: %w", configFile, err)
	}
	log.Printf("Config saved to %s", configFile)
	return nil
}

// loadWhitelist loads the whitelist from whitelist.json
func loadWhitelist() (map[string]bool, error) {
	whitelist := make(map[string]bool)
	data, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Whitelist file '%s' not found, starting with empty whitelist and creating file.", whitelistFile)
			// Save empty whitelist to create the file
			if saveErr := saveWhitelist(whitelist); saveErr != nil {
				log.Printf("Error creating default whitelist file: %v", saveErr)
			}
			return whitelist, nil // Return empty map
		}
		return nil, fmt.Errorf("error reading whitelist file %s: %w", whitelistFile, err)
	}

	if err := json.Unmarshal(data, &whitelist); err != nil {
		log.Printf("Error unmarshalling whitelist file %s: %v. Starting with empty whitelist.", whitelistFile, err)
		return make(map[string]bool), nil // Return empty map on error
	}

	log.Printf("Whitelist loaded from %s (%d entries)", whitelistFile, len(whitelist))
	return whitelist, nil
}

// saveWhitelist saves the whitelist to whitelist.json
func saveWhitelist(whitelist map[string]bool) error {
	config.mutex.RLock() // Use config mutex to protect whitelist access
	defer config.mutex.RUnlock()

	data, err := json.MarshalIndent(whitelist, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling whitelist: %w", err)
	}

	err = ioutil.WriteFile(whitelistFile, data, 0644)
	if err != nil {
		return fmt.Errorf("error writing whitelist file %s: %w", whitelistFile, err)
	}
	log.Printf("Whitelist saved to %s (%d entries)", whitelistFile, len(whitelist))
	return nil
}

// --- End Persistence Functions ---

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
	var err error
	// Load configuration from file
	config, err = loadConfig()
	if err != nil {
		log.Printf("Error loading config: %v. Continuing with defaults.", err)
		// loadConfig returns defaults on error, so we can continue
	}

	// Load whitelist from file
	whitelist, err := loadWhitelist()
	if err != nil {
		log.Printf("Error loading whitelist: %v. Starting with empty whitelist.", err)
		// loadWhitelist returns an empty map on error
	}
	config.Whitelist = whitelist // Assign loaded whitelist to config

	messageCounter = MessageCounter{
		messages: make([]time.Time, 0, 100),
	}

	// Load environment variables from .env file (for token mainly)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Load admin ID from environment variables ONLY if not set in config file
	if config.AdminID == 0 {
		if adminIDStr := os.Getenv("ADMIN_ID"); adminIDStr != "" {
			if adminID, err := strconv.ParseInt(adminIDStr, 10, 64); err == nil {
				config.mutex.Lock()
				config.AdminID = adminID
				config.mutex.Unlock()
				log.Printf("Admin ID loaded from environment: %d (config file was empty)", adminID)
				// Save the config now that AdminID is potentially updated from env
				if err := saveConfig(config); err != nil {
					log.Printf("Error saving config after loading AdminID from env: %v", err)
				}
			} else {
				log.Printf("Invalid ADMIN_ID in environment: %v", err)
			}
		}
	} else {
		log.Printf("Admin ID loaded from config file: %d", config.AdminID)
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

		// Get message content for logging
		messageContent := msg.Text
		if msg.Sticker != nil {
			messageContent = fmt.Sprintf("[Sticker: %s]", msg.Sticker.Emoji)
		}

		// Skip if filtering is disabled (duration is 0)
		if muteDuration > 0 {
			muteUser(b, chat, sender, muteDuration, messageContent)
			deleteMessage(b, msg)
		}
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

	// Get message content for logging
	text := msg.Text
	if msg.Sticker != nil {
		text = msg.Sticker.Emoji
	}

	// Get a consistent message content for logging
	messageContent := text
	if msg.Sticker != nil {
		messageContent = fmt.Sprintf("[Sticker: %s]", msg.Sticker.Emoji)
	}

	// Check username for suspicious pattern (ends with 5+ digits)
	if hasSuspiciousUsername(sender.Username) {
		config.mutex.RLock()
		muteDuration := config.MuteDurationSuspiciousName
		config.mutex.RUnlock()

		// Skip if filtering is disabled (duration is 0)
		if muteDuration > 0 {
			muteUser(b, chat, sender, muteDuration, messageContent)
			deleteMessage(b, msg)
			return nil
		}
	}

	// Check for short messages (5 or fewer characters)
	if len(text) <= 5 && text != "" {
		config.mutex.RLock()
		muteDuration := config.MuteDurationShortMessage
		config.mutex.RUnlock()

		// Skip if filtering is disabled (duration is 0)
		if muteDuration > 0 {
			muteUser(b, chat, sender, muteDuration, messageContent)
			deleteMessage(b, msg)
			return nil
		}
	}

	// Check for non-Latin and non-Cyrillic characters
	if !isMember && containsNonLatinCyrillic(text) {
		config.mutex.RLock()
		muteDuration := config.MuteDurationNonLatinCyrillic
		config.mutex.RUnlock()

		// Skip if filtering is disabled (duration is 0)
		if muteDuration > 0 {
			muteUser(b, chat, sender, muteDuration, messageContent)
			deleteMessage(b, msg)
			return nil
		}
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
func muteUser(b *tb.Bot, chat *tb.Chat, user *tb.User, duration time.Duration, messageText string) {
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
		logf("Muted user %s for %v. Message: %s", user.Username, duration, messageText)
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

	// Format each mute duration, showing "disabled" if it's 0
	var nonLatinCyrillicStatus, shortMessageStatus, suspiciousNameStatus, antiRaidStatus string

	if config.MuteDurationNonLatinCyrillic == 0 {
		nonLatinCyrillicStatus = "disabled"
	} else {
		nonLatinCyrillicStatus = config.MuteDurationNonLatinCyrillic.String()
	}

	if config.MuteDurationShortMessage == 0 {
		shortMessageStatus = "disabled"
	} else {
		shortMessageStatus = config.MuteDurationShortMessage.String()
	}

	if config.MuteDurationSuspiciousName == 0 {
		suspiciousNameStatus = "disabled"
	} else {
		suspiciousNameStatus = config.MuteDurationSuspiciousName.String()
	}

	if config.MuteDurationAntiRaid == 0 {
		antiRaidStatus = "disabled"
	} else {
		antiRaidStatus = config.MuteDurationAntiRaid.String()
	}

	configText := fmt.Sprintf(
		"*Current Configuration:*\n"+
			"- Non-Latin/Cyrillic filtering: %s\n"+
			"- Short message filtering: %s\n"+
			"- Suspicious username filtering: %s\n"+
			"- Anti-raid mode mute duration: %s\n"+
			"- Anti-raid messages threshold: %d\n"+
			"- Anti-raid time window: %v\n"+
			"- Anti-raid mode active: %v\n"+
			"- Admin ID for logs: %d\n\n"+
			"Use the following commands to configure:\n"+
			"/whitelist_add @username\n"+
			"/whitelist_remove @username\n"+
			"/whitelist_list\n"+
			"/set_mute_non_latin_cyrillic [minutes] (0 to disable)\n"+
			"/set_mute_short_message [minutes] (0 to disable)\n"+
			"/set_mute_suspicious_name [hours] (0 to disable)\n"+
			"/set_mute_anti_raid [hours] (0 to disable)\n"+
			"/set_anti_raid_threshold [count]\n"+
			"/set_anti_raid_window [seconds]\n"+
			"/set_admin_id [telegram_id]",
		nonLatinCyrillicStatus,
		shortMessageStatus,
		suspiciousNameStatus,
		antiRaidStatus,
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

	// Save whitelist
	if err := saveWhitelist(config.Whitelist); err != nil {
		logf("Error saving whitelist: %v", err)
		// Inform admin about the save error? Maybe just log for now.
	}

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

	// Save whitelist
	if err := saveWhitelist(config.Whitelist); err != nil {
		logf("Error saving whitelist: %v", err)
	}

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
			usage = "Usage: /set_mute_non_latin_cyrillic [minutes] (set to 0 to disable filtering)"
		case "short_message":
			usage = "Usage: /set_mute_short_message [minutes] (set to 0 to disable filtering)"
		case "suspicious_name":
			usage = "Usage: /set_mute_suspicious_name [hours] (set to 0 to disable filtering)"
		case "anti_raid":
			usage = "Usage: /set_mute_anti_raid [hours] (set to 0 to disable filtering)"
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

	var message string
	if duration == 0 {
		message = fmt.Sprintf("Filtering for %s has been disabled", violationType)
		logf("Admin %s disabled filtering for %s", c.Message().Sender.Username, violationType)
	} else {
		message = fmt.Sprintf("Mute duration for %s set to %v %s", violationType, duration.Minutes(), unit)
		logf("Admin %s set mute duration for %s to %v %s", c.Message().Sender.Username, violationType, duration.Minutes(), unit)
	}

	_, err = b.Send(c.Message().Chat, message)

	// Save config
	if err := saveConfig(config); err != nil {
		logf("Error saving config: %v", err)
	}

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

	// Save config
	if err := saveConfig(config); err != nil {
		logf("Error saving config: %v", err)
	}

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

	// Save config
	if err := saveConfig(config); err != nil {
		logf("Error saving config: %v", err)
	}

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

	// Save config
	if err := saveConfig(config); err != nil {
		logf("Error saving config: %v", err)
	}

	return err
}

// isAdmin checks if the user is an admin of the chat or the configured admin
func isAdmin(b *tb.Bot, c tb.Context) bool {
	msg := c.Message()
	sender := msg.Sender
	chat := msg.Chat

	// Check if user is the configured admin
	config.mutex.RLock()
	configuredAdminID := config.AdminID
	config.mutex.RUnlock()

	// If user ID matches the configured admin ID, they're an admin regardless of chat type
	if configuredAdminID > 0 && sender.ID == configuredAdminID {
		return true
	}

	// For private chats, we've already checked if they're the configured admin
	// If they're not, they can't be an admin in a private chat
	if chat.Type == tb.ChatPrivate {
		_, err := b.Send(chat, "This command is only available to the configured admin")
		if err != nil {
			logf("Error sending admin-only message: %v", err)
		}
		return false
	}

	// For group chats, check if user is a chat admin
	chatMember, err := b.ChatMemberOf(chat, sender)
	if err != nil {
		logf("Error checking if user is admin: %v", err)
		return false
	}

	isAdmin := chatMember.Role == tb.Administrator || chatMember.Role == tb.Creator
	if !isAdmin {
		_, err = b.Send(chat, "This command is only available to administrators or the configured admin")
		if err != nil {
			logf("Error sending admin-only message: %v", err)
		}
	}

	return isAdmin
}
