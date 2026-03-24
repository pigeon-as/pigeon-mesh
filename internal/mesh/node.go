package mesh

import "encoding/json"

type Node struct {
	Name        string `json:"n"`
	PubKey      string `json:"pk"`
	Endpoint    string `json:"ep"`
	OverlayAddr string `json:"oa"`
	WgPort      int    `json:"wp,omitempty"`
}

func encodeNodeMeta(n Node) ([]byte, error) {
	return json.Marshal(n)
}

func decodeNodeMeta(data []byte) (Node, error) {
	var n Node
	err := json.Unmarshal(data, &n)
	return n, err
}
