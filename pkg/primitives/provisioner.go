package primitives

import (
	"github.com/threefoldtech/zbus"
	"github.com/threefoldtech/zoslight/pkg/gridtypes"
	"github.com/threefoldtech/zoslight/pkg/gridtypes/zos"
	"github.com/threefoldtech/zoslight/pkg/primitives/gateway"
	netlight "github.com/threefoldtech/zoslight/pkg/primitives/network-light"
	"github.com/threefoldtech/zoslight/pkg/primitives/qsfs"
	vmlight "github.com/threefoldtech/zoslight/pkg/primitives/vm-light"
	"github.com/threefoldtech/zoslight/pkg/primitives/volume"
	"github.com/threefoldtech/zoslight/pkg/primitives/zdb"
	"github.com/threefoldtech/zoslight/pkg/primitives/zlogs"
	"github.com/threefoldtech/zoslight/pkg/primitives/zmount"
	"github.com/threefoldtech/zoslight/pkg/provision"
)

// NewPrimitivesProvisioner creates a new 0-OS provisioner
func NewPrimitivesProvisioner(zbus zbus.Client) provision.Provisioner {
	managers := map[gridtypes.WorkloadType]provision.Manager{
		zos.ZMountType:           zmount.NewManager(zbus),
		zos.ZLogsType:            zlogs.NewManager(zbus),
		zos.QuantumSafeFSType:    qsfs.NewManager(zbus),
		zos.ZDBType:              zdb.NewManager(zbus),
		zos.NetworkLightType:     netlight.NewManager(zbus),
		zos.ZMachineLightType:    vmlight.NewManager(zbus),
		zos.VolumeType:           volume.NewManager(zbus),
		zos.GatewayNameProxyType: gateway.NewNameManager(zbus),
		zos.GatewayFQDNProxyType: gateway.NewFQDNManager(zbus),
	}

	return provision.NewMapProvisioner(managers)
}
