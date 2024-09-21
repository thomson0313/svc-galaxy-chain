package launcher

import (
	"github.com/ethereum/go-ethereum/params"
)

var (
	Bootnodes = []string{
		"enode://8b6384778f5930dc339b6463f5002b818ea4c2b8c382bd545cc8a7660dd67cc3a7de1c20666490079e3d27c37e6188eb2ccce1dd8b2ffd628644ce0d6451891d@167.172.93.213:15060",
		"enode://e8dfd6d15fc4bb0e02c87684283beddc77740f8250870629434d26fbc9bf47a35733c09f409c147cd21d7ca55fc29fbdc9f50eae9772908bd0ed43031af08166@64.227.184.27:15060",
		"enode://7b78a47c13f5c66682309233194cf2bdb042288b79e6d0adf8baa54f353b661606533444682493fecdf815ce7e1d50b9fc8118ec6e27e9d04708a5e6083f5951@146.190.96.86:15060",
	}
)

func overrideParams() {
	params.MainnetBootnodes = []string{}
	params.RopstenBootnodes = []string{}
	params.RinkebyBootnodes = []string{}
	params.GoerliBootnodes = []string{}
}
