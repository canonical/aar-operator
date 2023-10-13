# Anbox Application Registry (AAR) Charmed Operator

## Description

### Anbox Cloud

Anbox Cloud offers a software stack that runs Android applications in any cloud enabling high-performance
streaming of graphics to desktop and mobile client devices.

At its heart, it uses lightweight container technology instead of full virtual machines to achieve higher
density and better performance per host while ensuring security and isolation of each container. Depending
on the target platform, payload, and desired application performance (e.g. frame rate), more than
100 containers can be run on a single machine.

For containerization of Android, Anbox Cloud uses the well established and secure container hypervisor
LXD. LXD is secure by design, scales to a large number of containers and provides advanced resource
management for hosted containers.

Also have a look at the official Anbox Cloud website (https://anbox-cloud.io) for more information.

> NOTE: Anbox Cloud is a paid offering. You will need a Ubuntu Pro (https://ubuntu.com/pro) subscription
> for this charm to work. You can learn more at https://anbox-cloud.io

> **WARNING:** The *Ubuntu Pro (infra only)* subscription every Ubuntu user gets for free for
> personal use does **NOT** work and will result in a failed deployment! You either need a
> *Ubuntu Pro* or *Ubuntu Pro (apps only)* subscription to be able to deploy successfully.

### Application Registry

The Anbox Application Registry, or *AAR*, charm provides a central repository for applications created
on Anbox Cloud. It is extremely useful for larger deployments involving multiple regions in order to
keep applications in sync.

#### Client Types

There are two types of consumers that can connect to AAR:
- **Client/Pull Only**: A Read-Only Client which can only pull from the registry
- **Publisher/Push & Pull**: A Read-Write Client which can publish applications to the registry as well

## Usage

> **WARNING:** This charm requires a resource to work which is described as follows:
> ```yaml
> resources:
>   aar-snap:
>     type: file
>     description: Snap for Anbox Application Registry
>     filename: aar.snap
> ```
> This resource represents the AAR snap package which will be installed when the charm gets installed.

### Basic Usage

```sh
$ juju deploy aar --resource aar-snap=aar.snap
```

For more information on how to configure the Application Registry and its clients, visit the official documentation
on https://anbox-cloud.io/docs/installation/installation-application-registry

## Integrations (Relations)

### `aar` interface:

This interface is used to register a client and interact with AAR.

#### Provides Side:

```yaml
provides:
  client:
    interface: aar
  publisher:
    interface: aar
```
This interface is used by two integrations in the charm both corresponding to the [types of clients](#client-types) to register.
The data provided to the consumer charms looks like the following:
```yaml
certificate: <self-signed certificate of the registry>
fingerprint: <fingerprint of the certificate>
ip: <ipv4 address of the listener>
port: <port of the listener>
```

#### Requires Side:

The data provided to the provider side should look like the following:
```yaml
certificate: "-----BEGIN CERTIFICATE-----\n
            ....
            -----END CERTIFICATE-----\n"
mode: "publisher"
```

## Security
Security issues in the operator can be reported through [LaunchPad](https://wiki.ubuntu.com/DebuggingSecurity#How%20to%20File) on the [Anbox Cloud](https://bugs.launchpad.net/anbox-cloud) project. Please do not file GitHub issues about security issues.

## Contributing
Please see the [Juju SDK docs](https://juju.is/docs/sdk) for guidelines on enhancements to this charm following best practice guidelines, and [CONTRIBUTING.md](https://github.com/canonical/aar-operator/blob/main/CONTRIBUTING.md) for developer guidance.

## License
The AAR Charm is distributed under the Apache Software License, version 2.0.
