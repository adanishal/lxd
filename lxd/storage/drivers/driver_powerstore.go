package drivers

import (
	"errors"
	"strings"

	"github.com/canonical/lxd/lxd/migration"
	"github.com/canonical/lxd/lxd/operations"
	"github.com/canonical/lxd/lxd/storage/connectors"
	"github.com/canonical/lxd/shared"
	"github.com/canonical/lxd/shared/api"
	"github.com/canonical/lxd/shared/validate"
)

// powerStoreDefaultUser represents the default PowerStore user name.
const powerStoreDefaultUser = "admin"

var powerstoreSupportedConnectors = []string{
	connectors.TypeNVME,
}

var powerStoreLoaded bool
var powerStoreVersion string

type powerstore struct {
	common

	// Holds the low level connector for the PowerStore driver.
	// Use powerstore.connector() to retrieve the initialized connector.
	storageConnector connectors.Connector
}

// load is used to run one-time action per-driver rather than per-pool.
func (d *powerstore) load() error {
	// Done if previously loaded.
	if powerStoreLoaded {
		return nil
	}

	versions := connectors.GetSupportedVersions(powerstoreSupportedConnectors)
	powerStoreVersion = strings.Join(versions, " / ")
	powerStoreLoaded = true

	// Load the kernel modules of the respective connector, ignoring those that cannot be loaded.
	// Support for a specific connector is checked during pool creation. However, this
	// ensures that the kernel modules are loaded, even if the host has been rebooted.
	connector, err := d.connector()
	if err == nil {
		_ = connector.LoadModules()
	}

	return nil
}

// connector retrieves an initialized storage connector based on the configured
// PowerStore mode. The connector is cached in the driver struct.
func (d *powerstore) connector() (connectors.Connector, error) {
	if d.storageConnector == nil {
		connector, err := connectors.NewConnector(d.config["powerstore.mode"], d.state.OS.ServerUUID)
		if err != nil {
			return nil, err
		}

		d.storageConnector = connector
	}

	return d.storageConnector, nil
}

// isRemote returns true indicating this driver uses remote storage.
func (d *powerstore) isRemote() bool {
	return true
}

// Info returns info about the driver and its environment.
func (d *powerstore) Info() Info {
	return Info{
		Name:                         "powerstore",
		Version:                      powerStoreVersion,
		DefaultBlockSize:             d.defaultBlockVolumeSize(),
		DefaultVMBlockFilesystemSize: d.defaultVMBlockFilesystemSize(),
		OptimizedImages:              false,
		PreservesInodes:              false,
		Remote:                       d.isRemote(),
		VolumeTypes:                  []VolumeType{VolumeTypeCustom, VolumeTypeVM, VolumeTypeContainer, VolumeTypeImage},
		BlockBacking:                 false,
		RunningCopyFreeze:            false,
		DirectIO:                     false,
		IOUring:                      false,
		MountedRoot:                  false,
		PopulateParentVolumeUUID:     false,
		UUIDVolumeNames:              false,
	}
}

// FillConfig populates the storage pool's configuration file with the default values.
func (d *powerstore) FillConfig() error {
	if d.config["powerstore.user.name"] == "" {
		d.config["powerstore.user.name"] = powerStoreDefaultUser
	}

	// Try to discover the PowerStore operation mode.
	if d.config["powerstore.mode"] == "" {
		// Create temporary connector to check if NVMe/TCP kernel modules can be loaded.
		nvmeConnector, err := connectors.NewConnector(connectors.TypeNVME, "")
		if err != nil {
			return err
		}

		if nvmeConnector.LoadModules() == nil {
			d.config["powerstore.mode"] = connectors.TypeNVME
		}

		return errors.New("Failed to discover PowerStore mode")
	}

	return nil
}

// Create is called during pool creation and is effectively using an empty driver struct.
// WARNING: The Create() function cannot rely on any of the struct attributes being set.
func (d *powerstore) Create() error {
	err := d.FillConfig()
	if err != nil {
		return err
	}

	// Validate both pool and gateway here and return an error if they are not set.
	if d.config["powerstore.pool"] == "" {
		return errors.New("The powerstore.pool cannot be empty")
	}
	if d.config["powerstore.gateway"] == "" {
		return errors.New("The powerstore.gateway cannot be empty")
	}

	return nil
}

// Delete removes the storage pool from the storage device.
func (d *powerstore) Delete(op *operations.Operation) error {
	// If the user completely destroyed it, call it done.
	if !shared.PathExists(GetPoolMountPath(d.name)) {
		return nil
	}

	// On delete, wipe everything in the directory.
	return wipeDirectory(GetPoolMountPath(d.name))
}

// Validate checks that all provided keys are supported and that no conflicting or missing configuration is present.
func (d *powerstore) Validate(config map[string]string) error {
	rules := map[string]func(value string) error{
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.user.name)
		// Must have at least SystemAdmin role to give LXD full control over managed storage pools.
		// ---
		//  type: string
		//  defaultdesc: `admin`
		//  shortdesc: User for PowerStore Gateway authentication
		//  scope: global
		"powerstore.user.name": validate.IsAny,
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.user.password)
		//
		// ---
		//  type: string
		//  shortdesc: Password for PowerStore Gateway authentication
		//  scope: global
		"powerstore.user.password": validate.IsAny,
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.gateway)
		//
		// ---
		//  type: string
		//  shortdesc: Address of the PowerStore Gateway
		//  scope: global
		"powerstore.gateway": validate.Optional(validate.IsRequestURL),
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.gateway.verify)
		//
		// ---
		//  type: bool
		//  defaultdesc: `true`
		//  shortdesc: Whether to verify the PowerStore Gateway's certificate
		//  scope: global
		"powerstore.gateway.verify": validate.Optional(validate.IsBool),
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.pool)
		// If you want to specify the storage pool via its name, also set {config:option}`storage-powerstore-pool-conf:powerstore.domain`.
		// ---
		//  type: string
		//  shortdesc: ID of the PowerStore storage pool
		//  scope: global
		"powerstore.pool": validate.IsAny,
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.domain)
		// This option is required only if {config:option}`storage-powerstore-pool-conf:powerstore.pool` is specified using its name.
		// ---
		//  type: string
		//  shortdesc: Name of the PowerStore protection domain
		//  scope: global
		"powerstore.domain": validate.IsAny,
		// lxdmeta:generate(entities=storage-powerstore; group=pool-conf; key=powerstore.mode)
		// The mode gets discovered automatically if the system provides the necessary kernel modules.
		// This can be `nvme`.
		// ---
		//  type: string
		//  defaultdesc: the discovered mode
		//  shortdesc: How volumes are mapped to the local server
		//  scope: global
		"powerstore.mode": validate.Optional(validate.IsOneOf("nvme")),
	}

	err := d.validatePool(config, rules, d.commonVolumeRules())
	if err != nil {
		return err
	}

	newMode := config["powerstore.mode"]
	oldMode := d.config["powerstore.mode"]

	// Ensure powerstore.mode cannot be changed to avoid leaving volume mappings
	// and to prevent disturbing running instances.
	if oldMode != "" && oldMode != newMode {
		return errors.New("PowerStore mode cannot be changed")
	}

	return nil
}

// commonVolumeRules returns validation rules which are common for pool and volume.
func (d *powerstore) commonVolumeRules() map[string]func(value string) error {
	return map[string]func(value string) error{
		// lxdmeta:generate(entities=storage-powerstore; group=volume-conf; key=block.filesystem)
		// Valid options are: `btrfs`, `ext4`, `xfs`
		// If not set, `ext4` is assumed.
		// ---
		//  type: string
		//  condition: block-based volume with content type `filesystem`
		//  defaultdesc: same as `volume.block.filesystem`
		//  shortdesc: File system of the storage volume
		//  scope: global
		"block.filesystem": validate.Optional(validate.IsOneOf(blockBackedAllowedFilesystems...)),
		// lxdmeta:generate(entities=storage-powerstore; group=volume-conf; key=block.mount_options)
		//
		// ---
		//  type: string
		//  condition: block-based volume with content type `filesystem`
		//  defaultdesc: same as `volume.block.mount_options`
		//  shortdesc: Mount options for block-backed file system volumes
		//  scope: global
		"block.mount_options": validate.IsAny,
		// lxdmeta:generate(entities=storage-powerstore; group=volume-conf; key=block.type)
		//
		// ---
		//  type: string
		//  defaultdesc: same as `volume.block.type` or `thick`
		//  shortdesc: Whether to create a `thin` or `thick` provisioned volume
		//  scope: global
		"block.type": validate.Optional(validate.IsOneOf("thin", "thick")),
		// lxdmeta:generate(entities=storage-powerstore; group=volume-conf; key=size)
		// The size must be in multiples of 8 GiB.
		// See {ref}`storage-powerstore-limitations` for more information.
		// ---
		//  type: string
		//  defaultdesc: same as `volume.size`
		//  shortdesc: Size/quota of the storage volume
		//  scope: global
		"size": validate.Optional(validate.IsMultipleOfUnit("8GiB")),
	}
}

// Update applies any driver changes required from a configuration change.
func (d *powerstore) Update(changedConfig map[string]string) error {
	return nil
}

// Mount mounts the storage pool.
func (d *powerstore) Mount() (bool, error) {
	return true, nil
}

// Unmount unmounts the storage pool.
func (d *powerstore) Unmount() (bool, error) {
	return true, nil
}

// GetResources returns the pool resource usage information.
func (d *powerstore) GetResources() (*api.ResourcesStoragePool, error) {
	return nil, errors.New("Unimplemented")
}

// MigrationTypes returns the type of transfer methods to be used when doing migrations between pools in preference order.
func (d *powerstore) MigrationTypes(contentType ContentType, refresh bool, copySnapshots bool) []migration.Type {
	return nil
}
