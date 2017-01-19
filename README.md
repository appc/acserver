# acserver - App Container Server

acserver is a minimal implementation for a web server that supports having ACIs
pushed to it, and serving those ACIs to clients via [meta
discovery](https://github.com/appc/spec/blob/master/spec/discovery.md#meta-discovery).


# Configuration file

Configuration file is optional, acserver will use all default attributes if not provided

```yaml
api:
  serverName:           # if not provided, use dns of http requests
  port: 3000
  https: false
  username:             # disable basic auth security if not provided
  password:
storage:
  rootPath:             # where to store acis
  unsigned: true        # support unsigned acis
  allowOverride: true   # allow overriding aci that already exists in store
```

# public key

public key file must be placed in storage root directory with name `pubkeys.gpg`
