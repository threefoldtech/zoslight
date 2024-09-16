package nft

import (
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/go-co-op/gocron"
	"github.com/rs/zerolog/log"
	"github.com/threefoldtech/zos/pkg/environment"

	"github.com/pkg/errors"
)

// Apply applies the ntf configuration contained in the reader r
// if ns is specified, the nft command is execute in the network namespace names ns
func Apply(r io.Reader, ns string) error {
	var cmd *exec.Cmd

	if ns != "" {
		cmd = exec.Command("ip", "netns", "exec", ns, "nft", "-f", "-")
	} else {
		cmd = exec.Command("nft", "-f", "-")
	}

	cmd.Stdin = r

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Str("output", string(out)).Msg("error during nft")
		if eerr, ok := err.(*exec.ExitError); ok {
			return errors.Wrapf(err, "failed to execute nft: %v", string(eerr.Stderr))
		}
		return errors.Wrap(err, "failed to execute nft")
	}
	return nil
}

// UpdateNFTWhitelist periodically pull list of ips from config repo and
// update the nft white list
func UpdateNFTWhitelist(configFileUrl string) error {
	scheduler := gocron.NewScheduler(time.UTC)
	cron := "0 * * * *"

	updateWhitelist := func() error {
		ips, err := whiteList(configFileUrl)
		if err != nil {
			return err
		}

		cmds := []string{
			"nft flush chain inet filter output",
			"nft add rule inet filter output ct state established,related accept",
			"nft add rule inet filter output tcp dport 22 accept",
		}

		ipCmdTemplate := "nft add rule inet filter output ip daddr %s accept"
		blockCmd := "nft add rule inet filter output drop"

		for _, cmd := range cmds {
			if err := runCommand(cmd); err != nil {
				return nil
			}
		}

		for _, ip := range ips {
			if err := runCommand(fmt.Sprintf(ipCmdTemplate, ip)); err != nil {
				return nil
			}
		}

		if err := runCommand(blockCmd); err != nil {
			return nil
		}

		return nil
	}

	if err := updateWhitelist(); err != nil {
		return err
	}

	if _, err := scheduler.Cron(cron).Do(updateWhitelist); err != nil {
		return err
	}
	scheduler.StartAsync()

	return nil
}

func runCommand(cmdStr string) error {
	cmd := exec.Command("sh", "-c", cmdStr)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, output)
	}
	return nil
}

func whiteList(configFileUrl string) ([]string, error) {
	var cfg environment.Config
	var err error

	if configFileUrl != "" {
		cfg, err = environment.GetConfigForUrl(configFileUrl)
		if err != nil {
			return nil, err
		}
	} else {
		cfg, err = environment.GetConfig()
		if err != nil {
			return nil, err
		}
	}

	return cfg.Whitelist.Ips, nil
}
