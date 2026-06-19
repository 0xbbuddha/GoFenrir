package enumeration

import (
	"fmt"
	"sort"

	epm "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0"
	epmfunctions "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/functions"
	epmstructs "github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/e1af8308-5d1f-11c9-91a4-08002b14a0fa/3.0/structures"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/catalog"
	dcerpcclient "github.com/TheManticoreProject/Manticore/network/dcerpc/v5/client"
	"github.com/TheManticoreProject/Manticore/windows/guid"

	gofenrirsmb "github.com/0xbbuddha/GoFenrir/protocols/smb"
)

// RPCEndpoint is one registered endpoint from the endpoint mapper.
type RPCEndpoint struct {
	UUID       string // interface UUID in format-D (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	Version    string // "major.minor"
	Name       string // short name from catalog, e.g. "srvsvc" (empty if unknown)
	Protocol   string // MS-* document id, e.g. "MS-SRVS" (empty if unknown)
	Transport  string // protocol sequence, e.g. "ncacn_ip_tcp", "ncacn_np", "ncalrpc"
	Endpoint   string // port (TCP) or pipe/port name (np/lrpc)
	Annotation string // human-readable label registered by the service
}

// EnumRPCEndpoints enumerates all registered RPC endpoints via the endpoint mapper.
func EnumRPCEndpoints(session *gofenrirsmb.Session) ([]RPCEndpoint, error) {
	if err := session.TreeConnect("IPC$"); err != nil {
		return nil, fmt.Errorf("IPC$: %w", err)
	}

	transport, err := session.Client.RPCTransport(epm.PipeName)
	if err != nil {
		return nil, fmt.Errorf("open epmapper pipe: %w", err)
	}
	rpc := dcerpcclient.NewClient(transport)
	if err := rpc.Bind(epm.SyntaxID()); err != nil {
		return nil, fmt.Errorf("epm bind: %w", err)
	}
	defer rpc.Close()

	entries, err := epmfunctions.Lookup(rpc)
	if err != nil {
		return nil, fmt.Errorf("ept_lookup: %w", err)
	}

	db := catalog.Default()
	seen := make(map[string]bool)
	var result []RPCEndpoint

	for _, e := range entries {
		tower, err := e.DecodeTower()
		if err != nil {
			continue
		}

		// Floor 0 is the interface identifier floor (FloorProtoUUID = 0x0D).
		if len(tower.Floors) == 0 || tower.Floors[0].Protocol() != epmstructs.FloorProtoUUID {
			continue
		}
		f0 := tower.Floors[0]
		if len(f0.LHS) < 19 || len(f0.RHS) < 2 {
			continue
		}

		var ifaceGUID guid.GUID
		ifaceGUID.FromRawBytes(f0.LHS[1:17])
		major := uint16(f0.LHS[17]) | uint16(f0.LHS[18])<<8
		minor := uint16(f0.RHS[0]) | uint16(f0.RHS[1])<<8

		binding, err := tower.Binding()
		if err != nil {
			continue
		}

		uuidStr := ifaceGUID.ToFormatD()
		key := fmt.Sprintf("%s|%d.%d|%s|%s", uuidStr, major, minor, binding.ProtSeq, binding.Endpoint)
		if seen[key] {
			continue
		}
		seen[key] = true

		ep := RPCEndpoint{
			UUID:       uuidStr,
			Version:    fmt.Sprintf("%d.%d", major, minor),
			Transport:  binding.ProtSeq,
			Endpoint:   binding.Endpoint,
			Annotation: string(e.Annotation),
		}
		if iface, ok := db.Resolve(ifaceGUID, major, minor); ok {
			ep.Name = iface.Name
			ep.Protocol = iface.Protocol
		}

		result = append(result, ep)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].UUID != result[j].UUID {
			return result[i].UUID < result[j].UUID
		}
		if result[i].Transport != result[j].Transport {
			return result[i].Transport < result[j].Transport
		}
		return result[i].Endpoint < result[j].Endpoint
	})

	return result, nil
}
