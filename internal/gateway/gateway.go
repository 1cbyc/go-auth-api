package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Route represents a gateway route configuration
type Route struct {
	Path        string            `json:"path"`
	Target      string            `json:"target"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	StripPrefix bool              `json:"strip_prefix,omitempty"`
}

// Gateway represents the API gateway
type Gateway struct {
	routes []Route
	client *http.Client
}

// NewGateway creates a new API gateway instance
func NewGateway() *Gateway {
	return &Gateway{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AddRoute adds a route to the gateway
func (g *Gateway) AddRoute(route Route) {
	g.routes = append(g.routes, route)
}

// SetupRoutes configures the gateway routes
func (g *Gateway) SetupRoutes(router *gin.Engine) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().UTC(),
		})
	})

	// Gateway routes
	for _, route := range g.routes {
		route := route // Create local copy for closure
		router.Handle(route.Method, route.Path, g.handleRequest(route))
	}
}

// handleRequest creates a handler for a specific route
func (g *Gateway) handleRequest(route Route) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Build target URL
		targetPath := c.Request.URL.Path
		if route.StripPrefix {
			targetPath = strings.TrimPrefix(targetPath, route.Path)
		}

		targetURL := fmt.Sprintf("%s%s", route.Target, targetPath)
		if c.Request.URL.RawQuery != "" {
			targetURL += "?" + c.Request.URL.RawQuery
		}

		// Create request
		req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			return
		}

		// Copy headers
		for key, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		// Add route-specific headers
		for key, value := range route.Headers {
			req.Header.Set(key, value)
		}

		// Set timeout if specified
		if route.Timeout > 0 {
			ctx, cancel := context.WithTimeout(c.Request.Context(), route.Timeout)
			defer cancel()
			req = req.WithContext(ctx)
		}

		// Make request
		resp, err := g.client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
			return
		}
		defer resp.Body.Close()

		// Read response body
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
			return
		}

		// Copy response headers
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		// Set response status and body
		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

// LoadBalancer represents a simple load balancer
type LoadBalancer struct {
	servers []string
	current int
}

// NewLoadBalancer creates a new load balancer
func NewLoadBalancer(servers []string) *LoadBalancer {
	return &LoadBalancer{
		servers: servers,
		current: 0,
	}
}

// Next returns the next server in round-robin fashion
func (lb *LoadBalancer) Next() string {
	if len(lb.servers) == 0 {
		return ""
	}

	server := lb.servers[lb.current]
	lb.current = (lb.current + 1) % len(lb.servers)
	return server
}

// RequestTransformer handles request/response transformation
type RequestTransformer struct{}

// TransformRequest transforms the incoming request
func (rt *RequestTransformer) TransformRequest(req *http.Request) error {
	// Add request ID if not present
	if req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", generateRequestID())
	}

	// Add timestamp
	req.Header.Set("X-Request-Timestamp", time.Now().UTC().Format(time.RFC3339))

	return nil
}

// TransformResponse transforms the outgoing response
func (rt *RequestTransformer) TransformResponse(resp *http.Response) error {
	// Add response headers
	resp.Header.Set("X-Response-Timestamp", time.Now().UTC().Format(time.RFC3339))

	return nil
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
