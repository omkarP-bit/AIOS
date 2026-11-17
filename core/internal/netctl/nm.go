// Package netctl talks to NetworkManager over the system D-Bus.
//
// It never runs nmcli or any other command. The surface is deliberately small:
// list known connections, resolve one by UUID or id, and activate it. Anything
// that is not an existing connection profile is out of scope.
package netctl

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	nmDestination = "org.freedesktop.NetworkManager"
	nmPath        = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	settingsPath  = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")
	nmInterface   = "org.freedesktop.NetworkManager"
	settingsIface = "org.freedesktop.NetworkManager.Settings"
	connIface     = "org.freedesktop.NetworkManager.Settings.Connection"
	deviceIface   = "org.freedesktop.NetworkManager.Device"
	activeIface   = "org.freedesktop.NetworkManager.Connection.Active"
)

// ErrUnavailable means NetworkManager is not reachable on the system bus.
var ErrUnavailable = errors.New("NetworkManager is not available on the system bus")

// ErrNotAuthorized means polkit or the connection's permissions refused the
// activation. The operator may need to approve it interactively.
var ErrNotAuthorized = errors.New("NetworkManager refused the activation")

// Connection is one stored NetworkManager profile.
type Connection struct {
	Path      dbus.ObjectPath `json:"-"`
	UUID      string          `json:"uuid"`
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Interface string          `json:"interface"`
	SSID      string          `json:"ssid,omitempty"`
}

// Device is one NetworkManager device.
type Device struct {
	Path      dbus.ObjectPath `json:"-"`
	Interface string          `json:"interface"`
	State     uint32          `json:"state"`
	Type      uint32          `json:"device_type"`
}

// Active is one active connection.
type Active struct {
	Path      dbus.ObjectPath `json:"-"`
	UUID      string          `json:"uuid"`
	ID        string          `json:"id"`
	Interface string          `json:"interface"`
	State     uint32          `json:"state"`
	StateText string          `json:"state_text"`
}

// Activation is the result of asking NetworkManager to activate a profile.
type Activation struct {
	Connection Connection `json:"connection"`
	ActivePath string     `json:"active_path,omitempty"`
	State      uint32     `json:"state"`
	StateText  string     `json:"state_text"`
	Activated  bool       `json:"activated"`
	Already    bool       `json:"already_active"`
}

// Manager is a connection to the system bus.
type Manager struct {
	conn *dbus.Conn
}

// Open connects to the system bus. It does not require NetworkManager to be
// running; calls return ErrUnavailable if it is not.
func Open() (*Manager, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return &Manager{conn: conn}, nil
}

// Close releases the shared system bus connection.
func (m *Manager) Close() error {
	if m == nil || m.conn == nil {
		return nil
	}
	return m.conn.Close()
}

// Available reports whether NetworkManager answers a cheap property read.
func (m *Manager) Available() error {
	if m == nil {
		return ErrUnavailable
	}
	if _, err := m.stringProperty(nmPath, nmInterface+".Version"); err != nil {
		return unavailable(err)
	}
	return nil
}

// Connections returns every stored profile, sorted by id.
func (m *Manager) Connections() ([]Connection, error) {
	if m == nil {
		return nil, ErrUnavailable
	}
	var paths []dbus.ObjectPath
	if err := m.conn.Object(nmDestination, settingsPath).
		Call(settingsIface+".ListConnections", 0).Store(&paths); err != nil {
		return nil, unavailable(err)
	}
	out := make([]Connection, 0, len(paths))
	for _, path := range paths {
		conn, err := m.connection(path)
		if err != nil {
			continue
		}
		out = append(out, conn)
	}
	sortConnections(out)
	return out, nil
}

// Resolve finds a profile by exact UUID or exact id. An ambiguous id is an
// error so a plan can never bind to the wrong network.
func (m *Manager) Resolve(identifier string) (Connection, error) {
	all, err := m.Connections()
	if err != nil {
		return Connection{}, err
	}
	matches := []Connection{}
	for _, conn := range all {
		if conn.UUID == identifier || conn.ID == identifier {
			matches = append(matches, conn)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return Connection{}, fmt.Errorf("no NetworkManager connection matches %q", identifier)
	default:
		return Connection{}, fmt.Errorf("%q matches %d connections; use the UUID", identifier, len(matches))
	}
}

// ActiveConnections returns the current active connections.
func (m *Manager) ActiveConnections() ([]Active, error) {
	if m == nil {
		return nil, ErrUnavailable
	}
	var paths []dbus.ObjectPath
	if err := m.conn.Object(nmDestination, nmPath).
		Call("org.freedesktop.DBus.Properties.Get", 0, nmInterface, "ActiveConnections").
		Store(&paths); err != nil {
		return nil, unavailable(err)
	}
	out := make([]Active, 0, len(paths))
	for _, path := range paths {
		active, err := m.active(path)
		if err != nil {
			continue
		}
		out = append(out, active)
	}
	return out, nil
}

// Activate asks NetworkManager to bring up an existing profile and waits up
// to timeout for it to reach the activated state. A timeout is not a failure:
// the request is still pending, and Activation says so.
func (m *Manager) Activate(conn Connection, timeout time.Duration) (Activation, error) {
	if m == nil {
		return Activation{}, ErrUnavailable
	}
	result := Activation{Connection: conn}
	device, err := m.deviceFor(conn.Interface, conn.Type)
	if err != nil {
		return result, err
	}
	active, _ := m.activeFor(conn.UUID)
	if active.State == 2 {
		result.Already = true
		result.Activated = true
		result.State = active.State
		result.StateText = stateText(active.State)
		return result, nil
	}
	var activePath dbus.ObjectPath
	err = m.conn.Object(nmDestination, nmPath).
		Call(nmInterface+".ActivateConnection", 0, conn.Path, device.Path, dbus.ObjectPath("/")).
		Store(&activePath)
	if err != nil {
		return result, activationError(conn, err)
	}
	result.ActivePath = string(activePath)
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		current, err := m.active(activePath)
		if err == nil {
			result.State = current.State
			result.StateText = current.StateText
			if current.State == 2 {
				result.Activated = true
				return result, nil
			}
			if current.State == 4 {
				return result, fmt.Errorf("NetworkManager deactivated the connection before it became active")
			}
		}
		if time.Now().After(deadline) {
			result.StateText = stateText(result.State)
			return result, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (m *Manager) connection(path dbus.ObjectPath) (Connection, error) {
	var settings map[string]map[string]dbus.Variant
	if err := m.conn.Object(nmDestination, path).
		Call(connIface+".GetSettings", 0).Store(&settings); err != nil {
		return Connection{}, err
	}
	conn := Connection{Path: path}
	conn.UUID = variantString(settings["connection"]["uuid"])
	conn.ID = variantString(settings["connection"]["id"])
	conn.Type = variantString(settings["connection"]["type"])
	conn.Interface = variantString(settings["connection"]["interface-name"])
	if wireless, ok := settings["802-11-wireless"]; ok {
		conn.SSID = variantBytes(wireless["ssid"])
	}
	if conn.UUID == "" || conn.ID == "" {
		return Connection{}, errors.New("profile is missing id or uuid")
	}
	return conn, nil
}

func (m *Manager) active(path dbus.ObjectPath) (Active, error) {
	connectionPath, err := m.objectProperty(path, activeIface+".Connection")
	if err != nil {
		return Active{}, err
	}
	conn, _ := m.connection(connectionPath)
	state, _ := m.uintProperty(path, activeIface+".State")
	devices, _ := m.objectPathsProperty(path, activeIface+".Devices")
	iface := ""
	if len(devices) > 0 {
		iface, _ = m.stringProperty(devices[0], deviceIface+".Interface")
	}
	return Active{
		Path: path, UUID: conn.UUID, ID: conn.ID, Interface: iface,
		State: state, StateText: stateText(state),
	}, nil
}

func (m *Manager) activeFor(uuid string) (Active, error) {
	actives, err := m.ActiveConnections()
	if err != nil {
		return Active{}, err
	}
	for _, active := range actives {
		if active.UUID == uuid {
			return active, nil
		}
	}
	return Active{}, errors.New("no active connection")
}

func (m *Manager) deviceFor(iface, connectionType string) (Device, error) {
	devices, err := m.Devices()
	if err != nil {
		return Device{}, err
	}
	for _, device := range devices {
		if device.Interface == iface {
			return device, nil
		}
	}
	// A profile without an interface-name can use any compatible device.
	wantType := deviceTypeFor(connectionType)
	for _, device := range devices {
		if wantType != 0 && device.Type == wantType {
			return device, nil
		}
	}
	return Device{}, fmt.Errorf("no NetworkManager device matches interface %q", iface)
}

// Devices returns every NetworkManager device.
func (m *Manager) Devices() ([]Device, error) {
	if m == nil {
		return nil, ErrUnavailable
	}
	var paths []dbus.ObjectPath
	if err := m.conn.Object(nmDestination, nmPath).
		Call(nmInterface+".GetDevices", 0).Store(&paths); err != nil {
		return nil, unavailable(err)
	}
	out := make([]Device, 0, len(paths))
	for _, path := range paths {
		iface, err := m.stringProperty(path, deviceIface+".Interface")
		if err != nil {
			continue
		}
		state, _ := m.uintProperty(path, deviceIface+".State")
		deviceType, _ := m.uintProperty(path, deviceIface+".DeviceType")
		out = append(out, Device{Path: path, Interface: iface, State: state, Type: deviceType})
	}
	return out, nil
}

func (m *Manager) stringProperty(path dbus.ObjectPath, property string) (string, error) {
	variant, err := m.variantProperty(path, property)
	if err != nil {
		return "", err
	}
	value, _ := variant.Value().(string)
	return value, nil
}

func (m *Manager) uintProperty(path dbus.ObjectPath, property string) (uint32, error) {
	variant, err := m.variantProperty(path, property)
	if err != nil {
		return 0, err
	}
	switch value := variant.Value().(type) {
	case uint32:
		return value, nil
	case uint16:
		return uint32(value), nil
	case int32:
		return uint32(value), nil
	default:
		return 0, fmt.Errorf("property %s is not an unsigned integer", property)
	}
}

func (m *Manager) objectProperty(path dbus.ObjectPath, property string) (dbus.ObjectPath, error) {
	variant, err := m.variantProperty(path, property)
	if err != nil {
		return "", err
	}
	value, _ := variant.Value().(dbus.ObjectPath)
	return value, nil
}

func (m *Manager) objectPathsProperty(path dbus.ObjectPath, property string) ([]dbus.ObjectPath, error) {
	variant, err := m.variantProperty(path, property)
	if err != nil {
		return nil, err
	}
	value, _ := variant.Value().([]dbus.ObjectPath)
	return value, nil
}

func (m *Manager) variantProperty(path dbus.ObjectPath, property string) (dbus.Variant, error) {
	iface, name := splitProperty(property)
	var variant dbus.Variant
	if err := m.conn.Object(nmDestination, path).
		Call("org.freedesktop.DBus.Properties.Get", 0, iface, name).
		Store(&variant); err != nil {
		return dbus.Variant{}, err
	}
	return variant, nil
}

func splitProperty(property string) (string, string) {
	idx := strings.LastIndex(property, ".")
	if idx < 0 {
		return "", property
	}
	return property[:idx], property[idx+1:]
}

func variantString(value dbus.Variant) string {
	if value.Value() == nil {
		return ""
	}
	text, _ := value.Value().(string)
	return text
}

func variantBytes(value dbus.Variant) string {
	switch raw := value.Value().(type) {
	case []byte:
		return strings.TrimRight(string(raw), "\x00")
	case string:
		return raw
	default:
		return ""
	}
}

func sortConnections(connections []Connection) {
	for i := 1; i < len(connections); i++ {
		for j := i; j > 0 && strings.ToLower(connections[j].ID) < strings.ToLower(connections[j-1].ID); j-- {
			connections[j], connections[j-1] = connections[j-1], connections[j]
		}
	}
}

func deviceTypeFor(connectionType string) uint32 {
	switch connectionType {
	case "802-11-wireless":
		return 2
	case "802-3-ethernet":
		return 1
	default:
		return 0
	}
}

func stateText(state uint32) string {
	switch state {
	case 0:
		return "unknown"
	case 1:
		return "activating"
	case 2:
		return "activated"
	case 3:
		return "deactivating"
	case 4:
		return "deactivated"
	default:
		return "unknown"
	}
}

func unavailable(err error) error {
	if err == nil {
		return nil
	}
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) {
		switch dbusErr.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown",
			"org.freedesktop.DBus.Error.NameHasNoOwner":
			return fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	return err
}

func activationError(conn Connection, err error) error {
	var dbusErr dbus.Error
	if errors.As(err, &dbusErr) {
		switch dbusErr.Name {
		case "org.freedesktop.NetworkManager.NotAuthorized",
			"org.freedesktop.NetworkManager.AgentManager.InvalidIdentifier",
			"org.freedesktop.DBus.Error.AccessDenied":
			return fmt.Errorf("%w: %s", ErrNotAuthorized, dbusErr.Name)
		}
	}
	return fmt.Errorf("cannot activate %q: %w", conn.ID, err)
}
