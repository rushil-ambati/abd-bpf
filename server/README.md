# ABD BPF Server

Implementation of the ABD algorithm's server actor as an eBPF program.

The server supports two operations:

- `WRITE(tag, value, write_counter)`: Writes the value and tag to the server.
  - The tag must be greater than the current tag.
  - The write counter must be greater than the current write counter for the sender.
  - Returns `WRITE_ACK(write_counter)`.
- `READ(read_counter)`: Reads the value and tag from the server.
  - The read counter must be greater than the current read counter for the sender.
  - Returns `READ_ACK(tag, value, read_counter)`.

The server state is simply a value (in this example, a 32-bit unsigned integer) and an associated tag.
It also tracks a counter per-IP address.

This is an XDP program which filters packets containing ABD messages:

- The packet must be an IPv6 packet.
- The packet must be a UDP packet on port 4242.
- The packet must be a valid ABD message.

When a valid ABD message is received, the server:

- Processes the message, updating the server state if necessary.
- Modifies the packet in-place to with the response message.
- Sends the packet back on the same interface to the sender using the `XDP_TX` action.

The logic is modelled after this specification:

![ABD Server Actor Specification](https://cs.neea.dev/_assets/images/distributed/6OIMH9K.png)
