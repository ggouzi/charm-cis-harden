# charm-cis-hardening

Charmhub package name: charm-cis-hardening

More information: https://charmhub.io/charm-cis-hardening

This charm implements CIS (Center for Internet Security) hardening for Juju units.
It provides capabilities to install, configure, and audit security configurations
based on CIS benchmarks.


## Usage

### Pre-requisites

- This charm needs parent unit to be registered with a valid Ubuntu Pro token and have `usg` enabled.

You can use the following subordinate [ubuntu-advantage](https://charmhub.io/ubuntu-advantage). Ensure `usg` is enabled in the `services` config.
(*usg is not yet compatible with Ubuntu 24.04. Trying to deploy this charm on Ubuntu 24.04 will fail*)
```bash
juju deploy --channel=latest/stable ubuntu-advantage --config token=C1SnjuFGL9eDxWgmHHuKbrY9AcxDu --config services=esm-infra,usg
juju relate ubuntu-advantage ubuntu
``

#### Deploy the charm
```bash
# Deploy charm
juju deploy --channel=latest/edge charm-cis-hardening cis-hardening-ubuntu
```

#### Configure charm
```bash
juju config cis-hardening-ubuntu pre-hardening-script=@pre-hardening-script.sh
juju config cis-hardening-ubuntu tailoring-file="$(base64 custom-tailoring.xml)"
juju relate cis-hardening-ubuntu ubuntu # Or any other machine charm
```

This assumes machine unit has already a Ubuntu Pro token attached. Either through cloud-init or through `ubuntu-advantage` subordinate charm.


Subordinate charm should now be in active/idle status waiting for hardening
```bash
cis-hardening-ubuntu/0*  active   idle   Ready for CIS hardening. Run 'harden' action
```

#### Execute usg
```bash
juju run cis-hardening-ubuntu/0 -- harden
```

The status should now be blocked, waiting for human action.

```bash
cis-hardening-ubuntu/0*  blocked   idle   Hardening complete. Please reboot the unit
```

#### Reboot the unit
```bash
juju ssh cis-hardening-ubuntu/0 -- sudo reboot
```

After reboot, the status should be active/idle

```bash
cis-hardening-ubuntu/0*  active   idle   Unit is hardened. Use 'audit' action to check compliance
```

#### Audit the unit post-hardening
```bash
juju run cis-hardening-ubuntu/0 -- audit
```

Once finished, the status of the unit should be active/idle with the following message:
```bash
charm-cis-hardening/0* active   idle   Audit finished. Result file: /tmp/audit.results.html
```

#### (Optional) Fetch the results
```bash
juju run charm-cis-hardening/0 -- get-results format=html | base64 -d > usg-result.html
juju run charm-cis-hardening/0 -- get-results format=xml | base64 -d > usg-result.xml
```

#### (Optional) Fetch the status
The `get-status` action returns information about whether the unit is hardened/audit and when happened the latest actions.
It also returns the hardening percentage/score


```bash
juju run cis-hardening-ubuntu/0 -- get-status | yq .
result:
  audited: "True"
  hardened: "True"
  last-audit-files: ops.framework.StoredList(['/tmp/audit.results.xml', '/tmp/audit.results.html'])
  last-audit-result: 85.522530%
  last-audit-time: 2024-11-17T11:51:12.176138
  last-harden-time: 2024-11-17T11:47:34.967484
```

Squeleton for `tailoring.xml` can be generated using `sudo usg generate-tailoring cis_level2_server tailoring.xml`. Adjust it by enabling/disabling specific rules to match the current unit you wish to harden

## Other resources

- [Charm](https://charmhub.io/charm-cis-hardening)

- [Contributing](CONTRIBUTING.md)

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
