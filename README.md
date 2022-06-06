# In-Network Memory

## About

A P4 implementation of a method to store data in the memory of network switches.

## Usage

1. Run `make` in the source folder. This should start a Mininet instance with the P4 program installed on the switches.
2. A small Python library can be used to test the protocol. You should run Python from the Mininet command prompt.
For example:
```py
mininet> h1 python3
>>> import mem
>>> # You can now use the library.
```

## Protocol Details

Memory headers can be the payload of IPv4 packets where the IPv4 packet's protocol is set to `0xFD`. The switches will perform forwarding unless they encounter an IPv4 packet addressed to them that also contains a memory header. In that case they should perform the memory operation and then return a response to the sender.

### Layout

The memory header's contents per byte:
| 0  | 1-4 | 5-8 |9-12|
|----|-----|-----|----|
|Code|Index|Value|Lock|

The content of the Code byte depends on whether it's a request or a response. All hosts should handle incoming memory headers as responses and all switches should handle them as requests as long as they are addressed to them. There is no way to determine the kind of a memory header otherwise.
|Code|Request|Response   |
|---:|-------|-----------|
|0   |Lock   |Ok         |
|1   |Unlock |Wrong Lock |
|2   |Read   |Wrong Index|
|3   |Write  |-          |

### Behavior

Any request with an invalid Index should respond with Wrong Index without performing an operation. The Index in the request should always correspond to the Index in the response. If the response Code is non-zero then the contents of Value and Lock are undefined. A Lock value of 0 is considered unlocked.
|Request|Behavior|
|-|-|
|Lock|If the cell is locked then Code in the response is set to Wrong Lock. Otherwise the cell will remember the value of Lock as its password then in the response Value is set to the cell's contents and Lock is the same as in the request.|
|Unlock|If Lock differs from the cell's password then Code in the response is set to Wrong Lock. Otherwise the cell is unlocked and in the response Lock is set to 0.|
|Read|If Lock differs from the cell's password then Code in the response is set to Wrong Lock. Otherwise in the response Value is set to the cell's value and Lock to the request's Lock.|
|Write|If Lock differs from the cell's password then Code in the response is set to Wrong Lock. Otherwise the cell is set to Value and in the response Value and Lock are set to the Value and Lock of the request.|

## The Python API

`mem.NetworkMemory(cell,source_ip,target_ip,password)`

All relevant functionality has been implemented on the `NetworkMemory` class.
* **cell:** the memory cell inside of the target switch to be accessed.
* **source_ip:** the ip to send results to.
* **target_ip:** the ip the target switch listens to.
* **password:** the secret by which the memory cell can be locked. 0 is valid, but the cell will actually never lock.
Example:
```py
m = mem.NetworkMemory(12,"10.0.1.1","10.0.3.42",1234)
```
___
`mem.NetworkMemory.lock()`

Blocks until the specified cell's lock can be taken. Note that locks are not reentrant: a lock can only be taken if it's unlocked even if the password is the same.

Returns the value of the cell at the time the lock was taken.

Raises `CellIndexError` if the switch has no such memory cell.
Example:
```py
print(m.lock())
```
___
`mem.NetworkMemory.unlock()`

Unlocks the specified cell.

Raises `CellIndexError` if the switch has no such memory cell.

Raises `LockError` if the cell could not be unlocked either because it was not locked or was locked with a different password.
___
`mem.NetworkMemory.unlocked_write(value)`

Blocks until the cell becomes unlocked and then writes the value into it.

* **value:** the value to write into the cell.

Raises `CellIndexError` if the switch has no such memory cell.
Example:
```py
m.unlocked_write(1)
```
___
`mem.NetworkMemory.locked_write(value)`

Writes the value into the cell with a taken lock.

* **value:** the value to write into the cell.

Raises `CellIndexError` if the switch has no such memory cell.

Raises `LockError` if the cell is unlocked or was locked by a different password.

Example:
```py
m.locked_write(1)
```
___
`mem.NetworkMemory.unlocked_read()`

Blocks until the cell becomes unlocked and then reads its value.
Raises `CellIndexError` if the switch has no such memory cell.
Example:
```py
print(m.unlocked_read())
```
___
`mem.NetworkMemory.locked_read()`

Reads the value of a locked cell.

Raises `CellIndexError` if the switch has no such memory cell.

Raises `LockError` if the cell is unlocked or was locked by a different password.

Example:
```py
print(m.locked_read())
```
___
`mem.NetworkMemory.read_write(f)`

Performs a blocking atomic read-write operation on the cell by the provided function. It's equivalent to the following sequence: `lock` -> `locked_read` -> `locked_write` -> `unlock`

Raises `CellIndexError` if the switch has no such memory cell.

Example:
```py
m.read_write(lambda x: x*2)
```
___
The API internally uses [Scapy](https://scapy.net/).

## The P4 Program

The P4 program uses two registers of equal length to store the values of the memory cells and their associated passwords. Two tables are utilized: one for forwarding and another for determining if a memory header was intended for the switch to process. First, the memory table is examined, but only if a memory header is present. If it finds a match, the memory operation is executed and the source and destination IP addresses are swapped. Second, forwarding happens regardless of a memory operation. Because executing a memory operation swaps the source and destination IPs this ensures that a response is sent out the correct egress port.