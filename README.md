# Stellar Experiments

A rust implementation of the [js-stellar-node-connector](https://github.com/stellarbeat/js-stellar-node-connector).

This acts as a mediator between the user(you) and the Stellar Node.

## Usage
### Provide the necessary structures:`NodeInfo`, `ConnConfig` with `fn new(...)`
The `NodeInfo` contains the information of the Stellar Node to connect to. Except the address and the port.
```rust
pub struct NodeInfo {
    pub ledger_version: u32,
    pub overlay_version: u32,
    pub overlay_min_version: u32,
    pub version_str: Vec<u8>,
    pub network_id: NetworkId,
}
```
Check out [Stellarbeat.io](https://stellarbeat.io/) for examples.

The `ConnConfig` is a configuration for connecting to the Stellar Node. It is here where we specify the address and port.
```rust
pub struct ConnConfig {
    /// Stellar Node Address
    address: String,
    /// Stellar Node port
    port: u32,
    secret_key: SecretKey,
    pub auth_cert_expiration: u64,
    pub recv_tx_msgs: bool,
    pub recv_scp_messages: bool,
    pub remote_called_us: bool,
    /// how long to wait for the Stellar Node's messages.
    timeout_in_secs: u64,
    /// number of retries to wait for the Stellar Node's messages and/or to connect back to it.
    retries:u8
}
```

### Connecting and Listening to Stellar Node
The `UserControls` is used to connect to the StellarNode. The function `connect()` accepts two parameters:
* `NodeInfo`
* `ConnConfig`
```rust
let user = UserControls::connect(node_info, conn_cfg);
```
The `UserControls` is also used to listen and send messages to the Stellar Node. 
* `send(StellarMessage)` - an async method to send `StellarMessage` to the StellarNode
* `recv()` - an async method which receives a `StellarNodeMessage`. The `StellarNodeMessage` is an enum of 4 variants:
    ```rust
    pub enum StellarNodeMessage {
      /// Successfully connected to the node
      Connect {
          pub_key: PublicKey,
          node_info: NodeInfo,
      },
      /// Stellar messages from the node
      Data {
          p_id: u32,
          msg_type: MessageType,
          msg: StellarMessage,
      },

      Error(String),
      Timeout,
    }
    ```
### Interpreting the `StellarNodeMessage`
* `Connect` -> interprets a successful connection to Stellar Node. It contains the PublicKey and the NodeInfo
* `Data` -> a wrapper of a StellarMessage and additional fields: the message type and the unique p_id(process id)
* `Timeout` -> a todo
* `Error` -> a todo

### Collecting Messages
The `ScpMessageCollector` is another structure to hold mappings between the slots, transactions, transactionsets, and their hashes.
```rust
    pub struct ScpMessageCollector {
        /// holds the mapping of the Slot Number(key) and the ScpEnvelopes(value)
        envelopes_map: EnvelopesMap,
        /// holds the mapping of the Slot Number(key) and the TransactionSet(value)
        txset_map: TxSetMap,
        /// holds the mapping of the Transaction Hash(key) and the Slot Number(value)
        tx_hash_map: TxHashMap,
        /// Holds the transactions that still have to be processed but were not because not enough scp messages are available yet.
        pending_transactions: Vec<TransactionEnvelope>,
        public_network: bool,
    }
```

To run the demo.rs, execute
```
 RUST_LOG=info cargo run mainnet
```
and you should be able to see in the terminal:
```
[2022-11-14T18:08:24Z INFO  stellar_relay::connection::connector::message_handler] Hello message processed successfully
[2022-11-14T18:08:25Z INFO  stellar_relay::connection::connector::message_handler] Handshake completed
[2022-11-14T18:08:28Z INFO  demo::collector] Adding received SCP envelopes for slot 43568056
[2022-11-14T18:08:29Z INFO  demo::collector] Inserting received transaction set for slot 43568056
[2022-11-14T18:08:33Z INFO  demo::collector] Adding received SCP envelopes for slot 43568057
[2022-11-14T18:08:34Z INFO  demo::collector] Inserting received transaction set for slot 43568057
[2022-11-14T18:08:39Z INFO  demo::collector] Adding received SCP envelopes for slot 43568058

```

Here is an example in the terminal when disconnection/reconnection happens:
```
[2022-11-14T18:09:32Z INFO  demo::collector] Adding received SCP envelopes for slot 43568067
[2022-11-14T18:09:33Z INFO  demo::collector] Inserting received transaction set for slot 43568067
[2022-11-14T18:09:37Z INFO  demo::collector] Adding received SCP envelopes for slot 43568068
[2022-11-14T18:09:47Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 0
[2022-11-14T18:09:57Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 1
[2022-11-14T18:10:07Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 2
[2022-11-14T18:10:11Z INFO  demo::collector] Inserting received transaction set for slot 43568068
[2022-11-14T18:10:22Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 0
[2022-11-14T18:10:32Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 1
[2022-11-14T18:10:42Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 2
[2022-11-14T18:10:52Z ERROR stellar_relay::connection::services] deadline has elapsed for receiving messages. Retry: 3
[2022-11-14T18:10:52Z ERROR demo] timed out.
[2022-11-14T18:10:52Z INFO  stellar_relay::connection::services] Starting Handshake with Hello.
[2022-11-14T18:10:53Z INFO  stellar_relay::connection::connector::message_handler] Hello message processed successfully
[2022-11-14T18:10:53Z INFO  stellar_relay::connection::connector::message_handler] Handshake completed
[2022-11-14T18:10:54Z INFO  demo::collector] Adding received SCP envelopes for slot 43568081
[2022-11-14T18:10:55Z INFO  demo::collector] Inserting received transaction set for slot 43568081
[2022-11-14T18:10:59Z INFO  demo::collector] Adding received SCP envelopes for slot 43568082
[2022-11-14T18:10:59Z INFO  demo::collector] Inserting received transaction set for slot 43568082
```
^ The demo is based on  `public` validator: 45.55.99.75