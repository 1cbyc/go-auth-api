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

type Route struct {
	Path        string            `json:"path"`
	Target      string            `json:"target"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers,omitempty"`
	Timeout     time.Duration     `json:"timeout,omitempty"`
	StripPrefix bool              `json:"strip_prefix,omitempty"`
}

type Gateway struct {
	routes []Route
	client *http.Client
}

func NewGateway() *Gateway {
	return &Gateway{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (g *Gateway) AddRoute(route Route) {
	g.routes = append(g.routes, route)
}

func (g *Gateway) SetupRoutes(router *gin.Engine) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "healthy",
			"time":   time.Now().UTC(),
		})
	})

	for _, route := range g.routes {
		route := route // Create local copy for closure
		router.Handle(route.Method, route.Path, g.handleRequest(route))
	}
}

func (g *Gateway) handleRequest(route Route) gin.HandlerFunc {
	return func(c *gin.Context) {
		targetPath := c.Request.URL.Path
		if route.StripPrefix {
			targetPath = strings.TrimPrefix(targetPath, route.Path)
		}

		targetURL := fmt.Sprintf("%s%s", route.Target, targetPath)
		if c.Request.URL.RawQuery != "" {
			targetURL += "?" + c.Request.URL.RawQuery
		}

		req, err := http.NewRequest(c.Request.Method, targetURL, c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
			return
		}

		for key, values := range c.Request.Header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}

		for key, value := range route.Headers {
			req.Header.Set(key, value)
		}

		if route.Timeout > 0 {
			ctx, cancel := context.WithTimeout(c.Request.Context(), route.Timeout)
			defer cancel()
			req = req.WithContext(ctx)
		}

		resp, err := g.client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "Failed to forward request"})
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
			return
		}

		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}

		c.Data(resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
}

type LoadBalancer struct {
	servers []string
	current int
}

func NewLoadBalancer(servers []string) *LoadBalancer {
	return &LoadBalancer{
		servers: servers,
		current: 0,
	}
}

func (lb *LoadBalancer) Next() string {
	if len(lb.servers) == 0 {
		return ""
	}

	server := lb.servers[lb.current]
	lb.current = (lb.current + 1) % len(lb.servers)
	return server
}

type RequestTransformer struct{}

func (rt *RequestTransformer) TransformRequest(req *http.Request) error {
	if req.Header.Get("X-Request-ID") == "" {
		req.Header.Set("X-Request-ID", generateRequestID())
	}

	req.Header.Set("X-Request-Timestamp", time.Now().UTC().Format(time.RFC3339))

	return nil
}

func (rt *RequestTransformer) TransformResponse(resp *http.Response) error {
	resp.Header.Set("X-Response-Timestamp", time.Now().UTC().Format(time.RFC3339))

	return nil
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d", time.Now().UnixNano())
}
