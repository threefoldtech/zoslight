package public

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/threefoldtech/zos4/pkg"
	"github.com/threefoldtech/zos4/pkg/gridtypes"
	"github.com/threefoldtech/zos4/pkg/netlight/bridge"
	"github.com/threefoldtech/zos4/pkg/netlight/namespace"
	"github.com/threefoldtech/zos4/pkg/netlight/types"
)

func TestCreatePublicNS(t *testing.T) {
	iface := &pkg.PublicConfig{
		Type: pkg.MacVlanIface,
		IPv6: gridtypes.IPNet{IPNet: net.IPNet{
			IP:   net.ParseIP("2a02:1802:5e:ff02::100"),
			Mask: net.CIDRMask(64, 128),
		}},
		GW6: net.ParseIP("fe80::1"),
	}

	defer func() {
		pubNS, _ := namespace.GetByName(types.PublicNamespace)
		err := namespace.Delete(pubNS)
		require.NoError(t, err)
	}()

	_, err := bridge.New("br-pub")
	require.NoError(t, err)
	defer func() {
		err = bridge.Delete("br-pub")
		require.NoError(t, err)
	}()
	err = setupPublicNS(pkg.StrIdentifier(""), iface)
	require.NoError(t, err)
}
