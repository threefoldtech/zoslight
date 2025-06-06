package powerd

import (
	"context"
	"crypto/ed25519"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	substrate "github.com/threefoldtech/tfchain/clients/tfchain-client-go"
	"github.com/threefoldtech/zbus"
	"github.com/threefoldtech/zosbase/pkg/environment"
	"github.com/threefoldtech/zosbase/pkg/events"
	"github.com/threefoldtech/zosbase/pkg/power"
	"github.com/threefoldtech/zosbase/pkg/stubs"
	"github.com/threefoldtech/zosbase/pkg/utils"
	"github.com/urfave/cli/v2"
)

const (
	module = "power"
)

// Module is entry point for module
var Module cli.Command = cli.Command{
	Name:  "powerd",
	Usage: "handles the node power events",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "broker",
			Usage: "connection string to the message `BROKER`",
			Value: "unix:///var/run/redis.sock",
		},
	},
	Action: action,
}

func action(cli *cli.Context) error {
	var (
		msgBrokerCon string = cli.String("broker")
		powerdLabel  string = "powerd"
	)

	ctx, _ := utils.WithSignal(cli.Context)
	utils.OnDone(ctx, func(_ error) {
		log.Info().Msg("shutting down")
	})

	env := environment.MustGet()

	cl, err := zbus.NewRedisClient(msgBrokerCon)
	if err != nil {
		return errors.Wrap(err, "failed to connect to message broker server")
	}

	zui := stubs.NewZUIStub(cl)
	// empty out zui errors for powerd
	if zuiErr := zui.PushErrors(cli.Context, powerdLabel, []string{}); zuiErr != nil {
		log.Info().Err(zuiErr).Send()
	}

	identity := stubs.NewIdentityManagerStub(cl)
	register := stubs.NewRegistrarStub(cl)

	nodeID, err := register.NodeID(ctx)
	if err != nil {
		if zuiErr := zui.PushErrors(cli.Context, powerdLabel, []string{err.Error()}); zuiErr != nil {
			log.Info().Err(zuiErr).Send()
		}
		return errors.Wrap(err, "failed to get node id")
	}

	twinID, err := register.TwinID(ctx)
	if err != nil {
		if zuiErr := zui.PushErrors(cli.Context, powerdLabel, []string{err.Error()}); zuiErr != nil {
			log.Info().Err(zuiErr).Send()
		}
		return errors.Wrap(err, "failed to get twin id")
	}

	sk := ed25519.PrivateKey(identity.PrivateKey(ctx))
	id, err := substrate.NewIdentityFromEd25519Key(sk)
	log.Info().Str("address", id.Address()).Msg("node address")
	if err != nil {
		return err
	}

	substrateGateway := stubs.NewSubstrateGatewayStub(cl)

	uptime, err := power.NewUptime(substrateGateway, id)
	if err != nil {
		return errors.Wrap(err, "failed to initialize uptime reported")
	}

	// start uptime reporting
	go uptime.Start(cli.Context)

	// if the feature is globally enabled try to ensure
	// wake on lan is set correctly.
	// then override the enabled flag
	enabled, err := power.EnsureWakeOnLan(cli.Context)
	if err != nil {
		return errors.Wrap(err, "failed to enable wol")
	}

	if !enabled {
		// if the zos nics don't support wol we can automatically
		// disable the feature
		log.Info().Msg("no wol support found by zos nic")
	}

	consumer, err := events.NewConsumer(msgBrokerCon, module)
	if err != nil {
		return errors.Wrap(err, "failed to to create event consumer")
	}

	// start power manager
	power, err := power.NewPowerServer(substrateGateway, consumer, enabled, env.FarmID, nodeID, twinID, uptime)
	if err != nil {
		return errors.Wrap(err, "failed to initialize power manager")
	}

	if err := power.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}
