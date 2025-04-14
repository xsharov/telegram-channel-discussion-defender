FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o telegram-bot .

# Use a smaller image for the final container
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/telegram-bot .
COPY --from=builder /app/.env.example .env.example

# Create a volume for persistent data
VOLUME ["/root/data"]

# Run the binary
CMD ["./telegram-bot"]
