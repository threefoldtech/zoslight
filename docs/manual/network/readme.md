# `network` type
Private network can span multiple nodes at the same time. Which means workloads (`VMs`) that live (on different node) but part of the same virtual network can still reach each other over this `private` network.

If one (or more) nodes are `public access nodes` you can also add your personal laptop to the nodes and be able to reach your `VMs` over `wireguard` network.

In the simplest form a network workload consists of:
- network range
- sub-range available on this node
- private key
- list of peers
  - each peer has public key
  - sub-range

Full network definition can be found [here](../../../pkg/gridtypes/zos/network.go)

## Private Networks

To reach vms on local nodes using wireguard you need to:
- Deploy a network on your local node with valid pairs so you can be able to connect to the vm from your machine and add a container to this network.
For example: 

```go
WGPrivateKey: wgKey,
WGListenPort: 3011,
Peers: []zos.Peer{
	{
		Subnet:      gridtypes.MustParseIPNet("10.1.2.0/24"),
		WGPublicKey: "4KTvZS2KPWYfMr+GbiUUly0ANVg8jBC7xP9Bl79Z8zM=",

		AllowedIPs: []gridtypes.IPNet{
			gridtypes.MustParseIPNet("10.1.2.0/24"),
			gridtypes.MustParseIPNet("100.64.1.2/32"),
		},
	},
},

```

> **Note:** make sure to use valid two wg key pairs for the container and your local machine.
- After the deployment the network can be accessed through wg with the following config.

```conf
[Interface]
Address = 100.64.1.2/32
PrivateKey = <your private key>

[Peer]
PublicKey = cYvKjMRBLj3o3e4lxWOK6bbSyHWtgLNHkEBxIv7Olm4=
AllowedIPs = 10.1.1.0/24, 100.64.1.1/32
PersistentKeepalive = 25
Endpoint = 192.168.123.32:3011
```
- Bring wireguard interface up `wg-quick up <config file>`
- Test the connection `wg`
![image](https://github.com/user-attachments/assets/ca0d37e2-d586-4e0f-ae98-2d70188492bd)

- Then you should be able to ping/access the container `ping 10.1.1.2`
![image](https://github.com/user-attachments/assets/d625a573-3d07-4980-afc0-4570acd7a21f)


For more details on how the network work please refer to the [internal manual](../../internals/network/readme.md)
