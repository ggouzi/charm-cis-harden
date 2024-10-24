# charm-cis-hardening

Charmhub package name: operator-template
More information: https://charmhub.io/charm-cis-hardening

Describe your charm in one or two sentences.

## Usage
```
# Using Keystone as an example
juju deploy keystone
juju config charm-cis-hardening pre-hardening-script=@test.sh
juju config charm-cis-hardening tailoring-file="$(base64 tailoring.xml)"
juju relate charm-cis-hardening keystone
juju run --wait=2m charm-cis-hardening/0 -- execute-cis
```

Squeleton for `tailoring.xml` can be generated using `sudo usg generate-tailoring cis_level2_server tailoring.xml`. Adjust it by enabling/disabling specific rules to match the current unit you wish to harden

## Other resources

- [Charm](https://charmhub.io/charm-cis-hardening)

- [Contributing](CONTRIBUTING.md)

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
