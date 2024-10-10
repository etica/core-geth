// Copyright 2019 The multi-geth Authors
// This file is part of the multi-geth library.
//
// The multi-geth library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The multi-geth library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the multi-geth library. If not, see <http://www.gnu.org/licenses/>.
package params

// EticaBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the Etica network.
var EticaBootnodes = []string{
	"enode://b0e97d2f1a37b2035a34b97f32fb31ddd93ae822b603c56b7f17cfb189631ea2ef17bfbed904f8bc564765634f2d9db0a128835178c8af9f1dde68ee6b5e2bf7@167.172.47.195:30303",
}

var dnsPrefixETICA = "enrtree://AJE62Q4DUX4QMMXEHCSSCSC65TDHZYSMONSD64P3WULVLSF6MRQ3K@" //not used set random value

var EticaDNSNetwork1 = dnsPrefixETICA + "all.etica.blockd.info" //not used set random value
