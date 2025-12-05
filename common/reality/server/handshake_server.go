package reality

import (
	"context"
	"fmt"
)

func (c *Conn) readClientHello(ctx context.Context) (*clientHelloMsg, error) {
	msg, err := c.readHandshake(nil)
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	var configForClient *Config
	originalConfig := c.config
	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(ctx, c, clientHello)
		if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
			c.sendAlert(alertInternalError)
			return nil, err
		} else if configForClient != nil {
			c.config = configForClient
		}
	}
	c.ticketKeys = originalConfig.ticketKeys(configForClient)

	clientVersions := clientHello.supportedVersions
	if clientHello.vers >= VersionTLS13 && len(clientVersions) == 0 {
		clientVersions = supportedVersionsFromMax(VersionTLS12)
	} else if len(clientVersions) == 0 {
		clientVersions = supportedVersionsFromMax(clientHello.vers)
	}
	c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return nil, fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers

	return clientHello, nil
}

func clientHelloInfo(ctx context.Context, c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		supportedVersions = supportedVersionsFromMax(clientHello.vers)
	}

	return &ClientHelloInfo{
		CipherSuites:      clientHello.cipherSuites,
		ServerName:        clientHello.serverName,
		SupportedCurves:   clientHello.supportedCurves,
		SupportedPoints:   clientHello.supportedPoints,
		SignatureSchemes:  clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Extensions:        clientHello.extensions,
		Conn:              c.conn,
		config:            c.config,
		ctx:               ctx,
	}
}
