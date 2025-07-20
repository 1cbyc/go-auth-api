package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

type Message struct {
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
	UserID    string                 `json:"user_id,omitempty"`
	RoomID    string                 `json:"room_id,omitempty"`
}

type Connection struct {
	ID     string
	UserID string
	RoomID string
	Conn   *websocket.Conn
	Send   chan []byte
	Hub    *Hub
	mu     sync.Mutex
}

type Hub struct {
	connections map[string]*Connection
	rooms       map[string]map[string]*Connection
	broadcast   chan *Message
	register    chan *Connection
	unregister  chan *Connection
	mu          sync.RWMutex
}

func NewHub() *Hub {
	return &Hub{
		connections: make(map[string]*Connection),
		rooms:       make(map[string]map[string]*Connection),
		broadcast:   make(chan *Message, 100),
		register:    make(chan *Connection, 100),
		unregister:  make(chan *Connection, 100),
	}
}

func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case conn := <-h.register:
			h.mu.Lock()
			h.connections[conn.ID] = conn
			if conn.RoomID != "" {
				if h.rooms[conn.RoomID] == nil {
					h.rooms[conn.RoomID] = make(map[string]*Connection)
				}
				h.rooms[conn.RoomID][conn.ID] = conn
			}
			h.mu.Unlock()

			welcomeMsg := &Message{
				Type:      "welcome",
				Data:      map[string]interface{}{"message": "Connected to WebSocket server"},
				Timestamp: time.Now(),
			}
			conn.SendMessage(welcomeMsg)

		case conn := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.connections[conn.ID]; ok {
				delete(h.connections, conn.ID)
				if conn.RoomID != "" {
					if room, exists := h.rooms[conn.RoomID]; exists {
						delete(room, conn.ID)
						if len(room) == 0 {
							delete(h.rooms, conn.RoomID)
						}
					}
				}
				close(conn.Send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.broadcastMessage(message)
		}
	}
}

func (h *Hub) broadcastMessage(message *Message) {
	data, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling message: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	if message.RoomID != "" {
		if room, exists := h.rooms[message.RoomID]; exists {
			for _, conn := range room {
				select {
				case conn.Send <- data:
				default:
					close(conn.Send)
					delete(h.connections, conn.ID)
				}
			}
		}
	} else {
		for _, conn := range h.connections {
			select {
			case conn.Send <- data:
			default:
				close(conn.Send)
				delete(h.connections, conn.ID)
			}
		}
	}
}

func (c *Connection) SendMessage(message *Message) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case c.Send <- data:
		return nil
	default:
		return fmt.Errorf("connection send buffer full")
	}
}

func (c *Connection) readPump() {
	defer func() {
		c.Hub.unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(512) // 512 bytes
	c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("Error unmarshaling message: %v", err)
			continue
		}

		msg.Timestamp = time.Now()
		msg.UserID = c.UserID
		msg.RoomID = c.RoomID

		c.handleMessage(&msg)
	}
}

func (c *Connection) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.Conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.Conn.WriteMessage(websocket.PongMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Connection) handleMessage(message *Message) {
	switch message.Type {
	case "join_room":
		c.joinRoom(message.Data["room_id"].(string))
	case "leave_room":
		c.leaveRoom()
	case "chat":
		c.broadcastToRoom(message)
	case "private_message":
		c.sendPrivateMessage(message)
	default:
		c.SendMessage(message)
	}
}

func (c *Connection) joinRoom(roomID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.RoomID != "" {
		c.Hub.mu.Lock()
		if room, exists := c.Hub.rooms[c.RoomID]; exists {
			delete(room, c.ID)
			if len(room) == 0 {
				delete(c.Hub.rooms, c.RoomID)
			}
		}
		c.Hub.mu.Unlock()
	}

	c.RoomID = roomID
	c.Hub.mu.Lock()
	if c.Hub.rooms[roomID] == nil {
		c.Hub.rooms[roomID] = make(map[string]*Connection)
	}
	c.Hub.rooms[roomID][c.ID] = c
	c.Hub.mu.Unlock()

	response := &Message{
		Type: "room_joined",
		Data: map[string]interface{}{
			"room_id": roomID,
			"message": fmt.Sprintf("Joined room: %s", roomID),
		},
		Timestamp: time.Now(),
	}
	c.SendMessage(response)
}

func (c *Connection) leaveRoom() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.RoomID == "" {
		return
	}

	roomID := c.RoomID
	c.RoomID = ""

	c.Hub.mu.Lock()
	if room, exists := c.Hub.rooms[roomID]; exists {
		delete(room, c.ID)
		if len(room) == 0 {
			delete(c.Hub.rooms, roomID)
		}
	}
	c.Hub.mu.Unlock()

	response := &Message{
		Type: "room_left",
		Data: map[string]interface{}{
			"room_id": roomID,
			"message": fmt.Sprintf("Left room: %s", roomID),
		},
		Timestamp: time.Now(),
	}
	c.SendMessage(response)
}

func (c *Connection) broadcastToRoom(message *Message) {
	if c.RoomID == "" {
		response := &Message{
			Type: "error",
			Data: map[string]interface{}{
				"message": "Not in a room",
			},
			Timestamp: time.Now(),
		}
		c.SendMessage(response)
		return
	}

	message.RoomID = c.RoomID
	c.Hub.broadcast <- message
}

func (c *Connection) sendPrivateMessage(message *Message) {
	targetUserID, ok := message.Data["target_user_id"].(string)
	if !ok {
		response := &Message{
			Type: "error",
			Data: map[string]interface{}{
				"message": "Target user ID required",
			},
			Timestamp: time.Now(),
		}
		c.SendMessage(response)
		return
	}

	c.Hub.mu.RLock()
	targetConn, exists := c.Hub.connections[targetUserID]
	c.Hub.mu.RUnlock()

	if !exists {
		response := &Message{
			Type: "error",
			Data: map[string]interface{}{
				"message": "User not found",
			},
			Timestamp: time.Now(),
		}
		c.SendMessage(response)
		return
	}

	privateMsg := &Message{
		Type: "private_message",
		Data: map[string]interface{}{
			"from_user_id": c.UserID,
			"message":      message.Data["message"],
		},
		Timestamp: time.Now(),
	}
	targetConn.SendMessage(privateMsg)

	response := &Message{
		Type: "message_sent",
		Data: map[string]interface{}{
			"to_user_id": targetUserID,
			"message":    "Message sent",
		},
		Timestamp: time.Now(),
	}
	c.SendMessage(response)
}

type WebSocketHandler struct {
	hub      *Hub
	upgrader websocket.Upgrader
}

func NewWebSocketHandler(hub *Hub) *WebSocketHandler {
	return &WebSocketHandler{
		hub: hub,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for now
			},
		},
	}
}

func (wh *WebSocketHandler) HandleWebSocket(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	conn, err := wh.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	connection := &Connection{
		ID:     userID.(string),
		UserID: userID.(string),
		Conn:   conn,
		Send:   make(chan []byte, 256),
		Hub:    wh.hub,
	}

	wh.hub.register <- connection

	go connection.writePump()
	go connection.readPump()
}

func (wh *WebSocketHandler) GetConnectionCount(c *gin.Context) {
	wh.hub.mu.RLock()
	count := len(wh.hub.connections)
	wh.hub.mu.RUnlock()

	c.JSON(http.StatusOK, gin.H{
		"connection_count": count,
	})
}

func (wh *WebSocketHandler) GetRoomInfo(c *gin.Context) {
	roomID := c.Param("room_id")

	wh.hub.mu.RLock()
	room, exists := wh.hub.rooms[roomID]
	wh.hub.mu.RUnlock()

	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Room not found"})
		return
	}

	userIDs := make([]string, 0, len(room))
	for userID := range room {
		userIDs = append(userIDs, userID)
	}

	c.JSON(http.StatusOK, gin.H{
		"room_id":    roomID,
		"user_count": len(room),
		"users":      userIDs,
	})
}

func (wh *WebSocketHandler) BroadcastMessage(c *gin.Context) {
	var req struct {
		Type   string                 `json:"type" binding:"required"`
		Data   map[string]interface{} `json:"data" binding:"required"`
		RoomID string                 `json:"room_id,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	message := &Message{
		Type:      req.Type,
		Data:      req.Data,
		RoomID:    req.RoomID,
		Timestamp: time.Now(),
	}

	wh.hub.broadcast <- message

	c.JSON(http.StatusOK, gin.H{
		"message": "Message broadcasted successfully",
	})
}
