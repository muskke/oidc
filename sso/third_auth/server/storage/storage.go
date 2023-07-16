package storage

import (
	"context"

	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
)

/**
* Storage 模拟数据库存储
 */

type authenticate interface {
	CheckUsernamePassword(ctx context.Context, username, password, id string) error
}

type MyStorage = op.Storage

func RegisterClients(registerClients ...*storage.Client) {
	registerClients = append(registerClients,
		storage.NativeClient("native"),
		storage.WebClient("web", ""),
		storage.WebClient("api", "secret"),
	)
	storage.RegisterClients(registerClients...)
}

func NewMultiStorage(issuers []string) authenticate {
	return storage.NewMultiStorage(issuers)
}
