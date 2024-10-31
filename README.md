# charm-cis-hardening

Charmhub package name: charm-cis-hardening

More information: https://charmhub.io/charm-cis-hardening

This charm implements CIS (Center for Internet Security) hardening for Juju units.
It provides capabilities to install, configure, and audit security configurations
based on CIS benchmarks.

## Usage
```
# Using Keystone as an example
juju deploy keystone
juju config charm-cis-hardening pre-hardening-script=@pre-hardening-script.sh
juju config charm-cis-hardening tailoring-file="$(base64 custom-tailoring.xml)"
juju relate charm-cis-hardening keystone
juju run --wait=2m charm-cis-hardening/0 -- execute-cis
juju ssh charm-cis-hardening/0 -- sudo reboot
juju run --wait=2m charm-cis-hardening/0 -- execute-audit
```

Squeleton for `tailoring.xml` can be generated using `sudo usg generate-tailoring cis_level2_server tailoring.xml`. Adjust it by enabling/disabling specific rules to match the current unit you wish to harden

## Dependencies

This charm needs all units to be registered with a valid Ubuntu Pro token.

You can use the following subordinate [ubuntu-advantage](https://charmhub.io/ubuntu-advantage). Ensure `usg` is enabled in the `services` config.

## Other resources

- [Charm](https://charmhub.io/charm-cis-hardening)

- [Contributing](CONTRIBUTING.md)

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
