package secrets

import "github.com/DE0CH/jarvis2/core/kernel"

// Routes: secrets' endpoints (GET /identity is added by kernel.Serve)
func (c *Secrets) Routes() map[string]kernel.Route {
	type named struct {
		Name  string `json:"name"`
		Nonce string `json:"nonce"`
		Store string `json:"store"`
		ID    string `json:"id"`
	}
	type master struct {
		Statement string        `json:"statement"`
		MasterSig string        `json:"masterSig"`
		Bundle    kernel.Sealed `json:"bundle"`
	}
	type finish struct {
		Pending   string                   `json:"pending"`
		Signature string                   `json:"signature"`
		Shares    map[string]kernel.Sealed `json:"shares"`
		Share     kernel.Sealed            `json:"share"`
	}
	one := func(fn func(named) (any, error)) kernel.Route {
		return func(body []byte) (any, error) {
			var in named
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return fn(in)
		}
	}
	return map[string]kernel.Route{
		"POST /state": func([]byte) (any, error) { return c.State() },
		"POST /claim": func(body []byte) (any, error) {
			var in master
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.Claim(in.Statement, in.MasterSig, in.Bundle)
		},
		"POST /wipe": func(body []byte) (any, error) {
			var in master
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.Wipe(in.Statement, in.MasterSig)
		},
		"POST /store-key": func(body []byte) (any, error) {
			var in struct {
				Phone string `json:"phone"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.StoreKey(in.Phone)
		},
		"POST /stores":                one(func(in named) (any, error) { return c.Stores(in.Nonce) }),
		"POST /stores/create":         one(func(in named) (any, error) { return c.CreateStore(in.Name) }),
		"POST /stores/mark-sensitive": one(func(in named) (any, error) { return c.MarkSensitive(in.Name) }),
		"POST /stores/write-key": func(body []byte) (any, error) {
			var in WriteKeyInput
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.WriteKey(in)
		},
		"POST /stores/versions": one(func(in named) (any, error) { return c.Versions(in.Store, in.Nonce) }),
		"POST /stores/restore/begin": func(body []byte) (any, error) {
			var in struct {
				Store string `json:"store"`
				Seq   int    `json:"seq"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.RestoreBegin(in.Store, in.Seq)
		},
		"POST /stores/restore/finish": func(body []byte) (any, error) {
			var in finish
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.RestoreFinish(in.Pending, in.Signature, in.Shares)
		},
		"POST /stores/restore/commit": func(body []byte) (any, error) {
			var in finish
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.RestoreCommit(in.Pending)
		},
		"POST /unlock/begin": one(func(in named) (any, error) { return c.UnlockBegin(in.Store) }),
		"POST /unlock/finish": func(body []byte) (any, error) {
			var in finish
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.UnlockFinish(in.Pending, in.Shares)
		},
		"POST /lock":     one(func(in named) (any, error) { return c.Lock(in.ID) }),
		"POST /unlocked": one(func(in named) (any, error) { return c.ListUnlocked(in.Nonce) }),
		"POST /deploy-keys/begin": func(body []byte) (any, error) {
			var in DeployKeyRequest
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.DeployKeyBegin(in)
		},
		"POST /deploy-keys/finish": func(body []byte) (any, error) {
			var in finish
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.DeployKeyFinish(in.Pending, in.Share, in.Signature)
		},
		"POST /pull": func(body []byte) (any, error) {
			var in struct {
				Grant kernel.SignedDoc `json:"grant"`
			}
			if err := kernel.Decode(body, &in); err != nil {
				return nil, err
			}
			return c.Pull(in.Grant)
		},
	}
}
