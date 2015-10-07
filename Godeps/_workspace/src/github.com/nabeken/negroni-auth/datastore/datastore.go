// Package datastore implements datastore (key, value pair) interface.
package datastore

// Datastore is an interface for retrieving value using key.
type Datastore interface {
	Get(key string) (value []byte, found bool)
}

// Simple is a simple struct stores only one key, value pair.
// This struct implement Datastore interface.
type Simple struct {
	Key   string
	Value []byte
}

// Simple.Get returns value using key.
func (d *Simple) Get(key string) ([]byte, bool) {
	if key == d.Key {
		return d.Value, true
	}
	return nil, false
}
