# SiFT v0.7 protocol diagrams

These diagrams summarize the SiFT v0.7 specification (`SiFT v0.7 specification.md`). Sequence numbers (sqn) are shown for the first messages of each direction; they keep increasing by one per message for the whole connection.

## Whole connection

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant C as Client
    participant S as Server (TCP 5150)

    Note over S: Startup: load SK_srv from server_privkey.pem<br/>(encrypted PKCS#35;8, passphrase), print fingerprint

    C->>S: TCP connect
    Note over C,S: MTP key unset. Only init_req / init_res allowed, sent in cleartext without mac

    rect rgb(255, 243, 224)
    Note over C,S: Init Protocol
    Note over C: Generate client_random (32 B)<br/>and ephemeral X25519 key pair
    C->>S: init_req [04 00, sqn 1]<br/>client_random, client_ecdh_pub
    Note over S: Check format. Generate server_random (32 B)<br/>and ephemeral X25519 key pair
    Note over S: sig = Ed25519_sign(SK_srv,<br/>"SiFT v0.7 init_res" | init_req | init_res_tbs)
    S->>C: init_res [04 10, sqn 1]<br/>server_random, server_ecdh_pub, PK_srv (DER), sig
    Note over S: Z = X25519(server_eph_priv, client_ecdh_pub)<br/>mtp_key = HKDF(...), install key, erase secrets
    Note over C: Verify sig with PK_srv from the message<br/>fingerprint = SHA-256(PK_srv DER)
    C->>U: Show fingerprint
    alt user rejects key
        U->>C: n
        C--xS: Close connection
    else user accepts key
        U->>C: y
        Note over C: Z = X25519(client_eph_priv, server_ecdh_pub)<br/>mtp_key = HKDF(...), install key, erase secrets
    end
    end

    Note over C,S: MTP key installed. All further messages are AES-256-GCM encrypted<br/>(nonce = sqn | rnd, header as AAD, 12 B mac). init_* now rejected

    rect rgb(227, 242, 253)
    Note over C,S: Login Protocol (also implicit key confirmation)
    U->>C: username, password
    C->>S: login_req [00 00, sqn 2]<br/>username, password
    Note over S: Valid mac means client has same key.<br/>Check password hash in users.txt
    S->>C: login_res [00 10, sqn 2]<br/>SHA-256(login_req)
    Note over C: Valid mac and matching hash means<br/>server has same key
    end

    rect rgb(232, 245, 233)
    Note over C,S: Commands Protocol (repeated)
    loop pwd, lst, chd, mkd, del
        C->>S: command_req [01 00]<br/>command, params
        S->>C: command_res [01 10]<br/>command, SHA-256(command_req), success/failure, results
    end
    end

    rect rgb(243, 229, 245)
    Note over C,S: Upload (upl command, then Upload Protocol)
    C->>S: command_req: upl, file name, size, file hash
    S->>C: command_res: upl, request hash, accept/reject
    opt accepted
        loop every 1024-byte fragment except the last
            C->>S: upload_req_0 [02 00] fragment
        end
        C->>S: upload_req_1 [02 01] last fragment
        S->>C: upload_res [02 10]<br/>file hash, file size
    end
    end

    rect rgb(255, 235, 238)
    Note over C,S: Download (dnl command, then Download Protocol)
    C->>S: command_req: dnl, file name
    S->>C: command_res: dnl, request hash, accept/reject, size, file hash
    opt accepted
        C->>S: dnload_req [03 00] ready / cancel
        opt ready
            loop every 1024-byte fragment except the last
                S->>C: dnload_res_0 [03 10] fragment
            end
            S->>C: dnload_res_1 [03 11] last fragment
            Note over C: Check size and hash
        end
    end
    end

    C--xS: Close connection (bye)
    Note over C,S: Any failed MTP check (version, type, rsv, sqn, mac) means<br/>the message is dropped and the connection closed
```

## Sub-protocol layering

```mermaid
flowchart TB
    subgraph app[Sub-protocols]
        direction LR
        INIT[Init Protocol<br/>04 xx]
        LOGIN[Login Protocol<br/>00 xx]
        CMD[Commands Protocol<br/>01 xx]
        UPL[Upload Protocol<br/>02 xx]
        DNL[Download Protocol<br/>03 xx]
    end
    MTP[Message Transfer Protocol<br/>16 B header: ver 00 07, typ, len, sqn, rnd, rsv]
    TCP[TCP connection, port 5150]

    INIT -- cleartext, no mac --> MTP
    LOGIN -- AES-GCM --> MTP
    CMD -- AES-GCM --> MTP
    UPL -- AES-GCM --> MTP
    DNL -- AES-GCM --> MTP
    INIT -. hands over mtp_key .-> MTP
    MTP --> TCP
```

## MTP states

```mermaid
stateDiagram-v2
    [*] --> NoKey: TCP connected, send/receive sqn = 0
    NoKey: Key unset
    NoKey: accept only init_req / init_res with sqn 1, cleartext
    Keyed: Key installed
    Keyed: accept only non-init types, AES-GCM with mtp_key
    NoKey --> Keyed: Init Protocol calls set_key(mtp_key)
    NoKey --> Closed: wrong type, bad format, bad signature,<br/>all-zero Z, or user rejects key
    Keyed --> Closed: bad version, type, rsv, sqn, or mac,<br/>sqn reaches ff ff, or client quits
    Closed --> [*]
```

## Key derivation

```mermaid
flowchart LR
    CE[client ephemeral X25519 key] --> Z
    SE[server ephemeral X25519 key] --> Z
    Z["Z = X25519 shared secret (32 B)<br/>reject if all-zero"] -->|IKM| HKDF
    CR[client_random] --> SALT
    SR[server_random] --> SALT
    SALT["salt = client_random | server_random (64 B)"] -->|salt| HKDF
    REQ[init_req payload, 129 B] --> TH
    RES[init_res payload, 347 B] --> TH
    TH["transcript_hash = SHA-256(init_req | init_res)"] --> INFO
    INFO["info = 'SiFT v0.7 MTP key' | transcript_hash"] -->|info| HKDF
    HKDF[HKDF-SHA256, L = 32] --> KEY[mtp_key: AES-256 key for MTP]
```
