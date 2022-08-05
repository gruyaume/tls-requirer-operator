# TLS Requirer Operator

## Description

Charm that requests TLS certificates using the tls-certificates interface and stores them. It 
doesn't do anything more than that. Simply asking for certificates. And storing them.

## Usage

```bash
juju deploy tls-requirer-operator
juju relate tls-requirer-operator <TLS Certificates Provider>
```

## Relations

- `tls-certificates`: Used for charms that require/provide TLS certificates.
