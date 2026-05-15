# Server-authoritative routing with Hostname mirroring

Runewarp keeps public routing authority on the Server and does not use Client registration or in-protocol Service identifiers. Operators mirror Public hostnames in Server Tunnels and Client Services so the Server can choose the Tunnel and the Client can choose the Service from the forwarded ClientHello, preserving transparent TLS passthrough without coupling the public data path to a control-plane negotiation.
