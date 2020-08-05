package storage

import (
	"fmt"
	"sort"

	"github.com/rs/zerolog/log"

	"github.com/google/uuid"

	"github.com/pkg/errors"

	"github.com/threefoldtech/zos/pkg"
	"github.com/threefoldtech/zos/pkg/storage/filesystem"
	"github.com/threefoldtech/zos/pkg/storage/zdbpool"
)

func (s *storageModule) Find(nsID string) (allocation pkg.Allocation, err error) {
	for _, pool := range s.pools {
		volumes, err := pool.Volumes()
		if err != nil {
			return allocation, errors.Wrapf(err, "failed to list volume on pool %s", pool.Name())
		}

		for _, volume := range volumes {
			// skip all non-zdb volume
			if !filesystem.IsZDBVolume(volume) {
				continue
			}

			zdb := zdbpool.New(volume.Path())

			if !zdb.Exists(nsID) {
				continue
			}

			// we found the namespace
			allocation = pkg.Allocation{
				VolumeID:   volume.Name(),
				VolumePath: volume.Path(),
			}

			return allocation, nil
		}
	}

	return pkg.Allocation{}, fmt.Errorf("not found")
}

// Allocate is responsible to make sure the subvolume used by a 0-db as enough storage capacity
// of specified size, type and mode
// it returns the volume ID and its path or an error if it couldn't allocate enough storage
func (s *storageModule) Allocate(nsID string, diskType pkg.DeviceType, size uint64, mode pkg.ZDBMode) (allocation pkg.Allocation, err error) {
	log := log.With().
		Str("type", string(diskType)).
		Uint64("size", size).
		Str("mode", string(mode)).
		Logger()

	if diskType != pkg.HDDDevice && diskType != pkg.SSDDevice {
		return allocation, pkg.ErrInvalidDeviceType{DeviceType: diskType}
	}

	log.Info().Msg("try to allocation space for 0-DB")

	for _, pool := range s.pools {
		if _, mounted := pool.Mounted(); !mounted {
			continue
		}

		// skip pool with wrong disk type
		if pool.Type() != diskType {
			continue
		}

		volumes, err := pool.Volumes()
		if err != nil {
			return allocation, errors.Wrapf(err, "failed to list volume on pool %s", pool.Name())
		}

		for _, volume := range volumes {

			// skip all non-zdb volume
			if !filesystem.IsZDBVolume(volume) {
				continue
			}

			zdb := zdbpool.New(volume.Path())

			if !zdb.Exists(nsID) {
				continue
			}

			// we found the namespace
			allocation = pkg.Allocation{
				VolumeID:   volume.Name(),
				VolumePath: volume.Path(),
			}

			return allocation, nil
		}
	}

	targetMode := zdbpool.IndexModeKeyValue
	if mode == pkg.ZDBModeSeq {
		targetMode = zdbpool.IndexModeSequential
	}

	// check for candidates in mounted pools first
	candidates, err := s.checkForZDBCandidates(size, diskType, true, targetMode)
	if err != nil {
		log.Error().Err(err).Msgf("failed to search on mounted pools")
	}

	var volume filesystem.Volume
	if len(candidates) > 0 {
		// reverse sort by free space
		sort.Slice(candidates, func(i, j int) bool {
			return candidates[i].Free > candidates[j].Free
		})

		volume = candidates[0]
	} else {
		// no candidates, so we have to try to create a new subvolume.
		// and start a new zdb instance
		name, err := genZDBPoolName()
		if err != nil {
			return allocation, errors.Wrap(err, "failed to generate new sub-volume name")
		}

		// we create the zdb instance with 0 (unlimited) because this subvolume is gonna
		// be used for a new instance of ZDB.
		volume, err = s.createSubvol(0, name, diskType)
		if err != nil {
			return allocation, errors.Wrap(err, "failed to create sub-volume")
		}
	}

	zdb := zdbpool.New(volume.Path())

	if err := zdb.Create(nsID, "", size); err != nil {
		return allocation, errors.Wrapf(err, "failed to create namespace directory: '%s/%s'", volume.Path(), nsID)
	}

	return pkg.Allocation{
		VolumeID:   volume.Name(),
		VolumePath: volume.Path(),
	}, nil

}

type zdbcandidate struct {
	filesystem.Volume
	Free uint64
}

func (s *storageModule) checkForZDBCandidates(size uint64, poolType pkg.DeviceType, mounted bool, targetMode zdbpool.IndexMode) ([]zdbcandidate, error) {
	var candidates []zdbcandidate
	for _, pool := range s.pools {
		_, poolIsMounted := pool.Mounted()
		if mounted != poolIsMounted {
			continue
		}

		// ignore pools which don't have the right device type
		if pool.Type() != poolType {
			continue
		}
		log.Debug().Msgf("checking pool %s for space", pool.Name())

		if !poolIsMounted && !mounted {
			log.Debug().Msgf("Mounting pool %s...", pool.Name())
			// if the pool is not mounted, and we are looking for not mounted pools, mount it first
			_, err := pool.MountWithoutScan()
			if err != nil {
				log.Error().Err(err).Msgf("failed to mount pool %s", pool.Name())
				return nil, err
			}
		}

		usage, err := pool.Usage()
		if err != nil {
			log.Error().Err(err).Msgf("failed to read usage of pool %s", pool.Name())
			return nil, err
		}

		volumes, err := pool.Volumes()
		if err != nil {
			log.Error().Err(err).Msgf("failed to list volume on pool %s", pool.Name())
			return nil, err
		}

		for _, volume := range volumes {
			// skip all non-zdb volume
			if !filesystem.IsZDBVolume(volume) {
				continue
			}

			volumeUsage, err := volume.Usage()
			if err != nil {
				log.Error().Err(err).Msgf("failed to list namespaces from volume '%s'", volume.Path())
				return nil, err
			}

			if volumeUsage.Size+size > usage.Size {
				// not enough space on this volume
				continue
			}

			zdb := zdbpool.New(volume.Path())

			// check if the mode is the same
			indexMode, err := zdb.IndexMode("default")
			if err != nil {
				log.Err(err).Str("namespace", "default").Msg("failed to read index mode")
				continue
			}

			if indexMode != targetMode {
				log.Info().Msg("skip because wrong mode")
				continue
			}

			candidates = append(
				candidates,
				zdbcandidate{
					Volume: volume,
					Free:   usage.Size - (volumeUsage.Size + size),
				})

			// if we are looking for not mounted pools, break here
			if !mounted {
				return candidates, nil
			}
		}

		if len(candidates) == 0 {
			log.Info().Msgf("Disk does not have enough space left to hold filesystem, shutting down again")
			err = pool.UnMount()
			if err != nil {
				log.Error().Err(err).Msgf("failed to unmount pool %s", pool.Name())
				return nil, err
			}
			err = pool.Shutdown()
			if err != nil {
				log.Error().Err(err).Msgf("failed to shutdown pool %s", pool.Name())
				return nil, err
			}
		}
	}
	return candidates, nil
}

const zdbPoolPrefix = "zdb"

func genZDBPoolName() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	name := zdbPoolPrefix + id.String()
	return name, nil
}
