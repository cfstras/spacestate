# Spacestate

Spacestate is a minimal implementation of the mumble protocol to facilitate getting status information from a running Mumble server.

Usage:

```bash
cargo run -- $server_hostname [$port]
```

Running the main binary will start an HTTP server at 127.0.0.1:8000.

## Status

Two methods are used:

1. Simple UDP Ping Packet as [specified here](https://wiki.mumble.info/wiki/Protocol)  
This ping packet only responds with latency, user numbers, and server version.

1. Full Mumble Protocol to gather information [Protobuf spec](https://mumble-protocol.readthedocs.io)  
This protocol is more complex, but allows gathering full user & channel information.

## Ping Packet

`HTTP GET /ping`

Status: Fully functional

Example response:
```json
{
  "data": {
    "version": [
      0,
      1,
      4,
      0
    ],
    "packet_id": 15366622843189944000,
    "users": 0,
    "max_users": 200,
    "bandwidth": 300000,
    "ping": 7
  },
  "time_since_refresh": 0
}
```

## Full Protocol

`HTTP GET /status`

Status: Unfinished

This implementation does not start a UDP voice tunnel after connecting, and the Mumble server does not seem to like this.
After the initial session and TLS negotiation, Mumble will _sometimes_ start sending channel & user information after a few seconds, but not always.

Example response:
```json
{
  "data": {
    "header": null,
    "channels": {
      "0": {
        "channel_id": 0,
        "parent": null,
        "name": "Our Mumble Server",
        "links": [],
        "description": "Test test<br>Test",
        "links_add": [],
        "links_remove": [],
        "temporary": null,
        "position": 0,
        "description_hash": null,
        "max_users": 0,
        "is_enter_restricted": false,
        "can_enter": true
      },
      "1": {
        "channel_id": 1,
        "parent": 8,
        "name": "Some Channel",
        "links": [],
        "description": "HTML description, sometimes with images as base64",
        "links_add": [],
        "links_remove": [],
        "temporary": null,
        "position": 0,
        "description_hash": null,
        "max_users": 0,
        "is_enter_restricted": false,
        "can_enter": true
      },
      "8": {
        "channel_id": 8,
        "parent": 0,
        "name": "Some Root Channel Name",
        "links": [],
        "description": "...",
        "links_add": [],
        "links_remove": [],
        "temporary": null,
        "position": 0,
        "description_hash": null,
        "max_users": 0,
        "is_enter_restricted": false,
        "can_enter": true
      },
    },
    "users": {
      "84": {
        "session": 84,
        "actor": null,
        "name": "ZiffBot",
        "user_id": null,
        "channel_id": 8,
        "mute": null,
        "deaf": null,
        "suppress": null,
        "self_mute": null,
        "self_deaf": null,
        "texture": null,
        "plugin_context": null,
        "plugin_identity": null,
        "comment": null,
        "hash": null,
        "comment_hash": null,
        "texture_hash": null,
        "priority_speaker": null,
        "recording": null,
        "temporary_access_tokens": [],
        "listening_channel_add": [],
        "listening_channel_remove": []
      }
    },
    "server_version": {
      "version": 66560,
      "release": "1.4.0",
      "os": "Linux",
      "os_version": "Alpine Linux v3.18 [x64]"
    },
    "suggest_config": null,
    "server_sync": {
      "session": 84,
      "max_bandwidth": 300000,
      "welcome_text": "Custom Channel Welcome text!",
      "permissions": 134744846
    },
    "server_config": {
      "max_bandwidth": null,
      "welcome_text": null,
      "allow_html": true,
      "message_length": 5000,
      "image_message_length": 131072,
      "max_users": 200
    }
  },
  "time_since_refresh": 0
}
```

## License

BSD 3-Clause, see [LICENSE.md]
