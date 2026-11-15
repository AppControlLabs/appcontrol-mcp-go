package main

import (
	"context"
	"log"
	"net/url"

	"github.com/AppControlLabs/appcontrol-mcp-go/tools"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// loopback answers through the service's local MCP API on this machine, with
// the port and token it publishes in the registry.
type loopback struct{}

func (loopback) Get(ctx context.Context, path string, params url.Values) (string, error) {
	c, err := getClient()
	if err != nil {
		return "", err
	}
	return c.Get(ctx, path, params)
}

func main() {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "AppControl",
		Version: "2.0.0",
	}, &mcp.ServerOptions{
		Instructions: tools.Instructions,
	})

	tools.Register(server, loopback{}, tools.Specs())

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
