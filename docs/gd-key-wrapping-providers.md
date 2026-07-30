# Backup Key Custody on the Global Dashboard

This document is for **CISOs**, **VPs of Security**, **operators**, and **auditors** who need to know where the key that opens a Global Dashboard backup lives, who can be compelled to use it, and what happens when a provider is retired or the hardware is gone.

## The one sentence that governs everything here

**A key-wrapping provider is custody, not recovery.**

It wraps the per-backup data key — the AES-256 key that encrypts one archive. It does not hold the GD's Tier-1 KEK, and the Tier-1 KEK is escrowed to no provider anywhere.

That distinction is not a detail. If a provider held the Tier-1 KEK, then anyone who could assume the IAM principal that reaches that provider could unwrap it over the network — and the guarantee that a copied disk or cloned VM cannot open your data would fall from *what your TPM is worth* to *what your cloud IAM policy is worth*. Recovering a Global Dashboard on replacement hardware still means re-establishing the KEK from your **offline recovery code**, exactly as it did before this feature existed.

If you find a runbook, a console message, or a support answer that describes a provider as a way to recover a deployment, it is wrong.

## What a provider actually does

Every v2 backup generates a fresh 256-bit data key, encrypts the archive with it, and then wraps that key. The wrapped result is stored beside the archive as `wrapped-key.bin`:

```
{ "v": 1, "scheme": "aws-kms", "ref": "arn:aws:kms:eu-central-1:...", "wrapped": "..." }
```

Restore reads the **scheme and reference the manifest recorded** and unwraps through that. It never consults current configuration. This is why a backup taken under a provider you have since retired still opens.

## The five schemes

| scheme | tier | where the wrapping key lives |
|---|---|---|
| `gd-tier1` | 1 | this host's TPM 2.0 / Secure Enclave, via the GD Tier-1 KEK |
| `aws-kms` | 2 | AWS KMS, in the region you configure |
| `azure-keyvault` | 2 | Azure Key Vault |
| `gcp-kms` | 2 | Google Cloud KMS, in the location you configure |
| `hashicorp-vault` | 2 | your Vault cluster's transit engine |

`gd-tier1` is the default and needs no configuration. It is **tier 1** because the key is sealed to hardware this machine holds: a copied disk cannot unseal it. The cloud providers are tier 2 because the key is held by a custodian who can be reached over the network — which buys FIPS-validated custody, provider-side rotation and provider-side audit, and costs you a dependency and a jurisdiction.

Neither is strictly better. `gd-tier1` is stronger against disk theft; an HSM is stronger against a compromise of this host. Choose on your threat model.

## Key custody is a residency question

A KMS key sits in a region, and the company operating it has a domicile. Those are different facts and FireAlive tracks them separately, because **an EU region operated by a US company is still reachable under US law**.

If you have declared a data-residency policy, the **Key custody** category governs which jurisdictions may hold your backup wrapping key. It behaves differently from the data-location categories in one deliberate way:

> Leaving `key_custody` unset **denies** external providers, where leaving `backup` unset permits.

That is because a key custodian can be *compelled to unwrap*. An operator who has declared a residency policy has not thereby authorised an unlisted jurisdiction to hold the key to their backups. Set the permitted regions explicitly.

If you have not enabled data residency at all, this gate makes no claim and external providers are unconstrained — declaring a residency policy is not a prerequisite for using a KMS.

**`azure-keyvault` and `hashicorp-vault` must have their jurisdiction declared**, because their configuration carries a hostname rather than a region token and inferring a country from a hostname would be a guess presented as a fact.

## Endpoint allow-listing

Two provider types take a URL you supply: `hashicorp-vault` (`vault_addr`) and `azure-keyvault` (`vault_url`). Set `GD_KMS_ALLOWED_HOSTS` to a comma-separated list of exact hostnames before configuring either.

- **Unset means nothing is authorised.** The check fails closed.
- Matching is **exact and hostname-only**: no wildcards, no subdomain semantics. `vault.example.com` does not authorise `evil.vault.example.com`.
- The host is checked when you save the configuration, when you test the connection, **and on every wrap and unwrap** — because a provider configured before you set the allow-list is otherwise unconstrained by it.

`aws-kms` and `gcp-kms` take a region and a key identifier rather than a URL, so no allow-list applies to them.

## Retiring instead of deleting

Two states look similar and are not:

- **Disabled** — do not use for new backups.
- **Retired** — do not use for new backups, *and* keep this provider so archives already wrapped with it can still be opened.

**A provider cannot be deleted while any backup depends on it.** The console shows the count before you try, the API refuses with an explanation, and the database refuses independently — so even a direct SQL statement that bypasses the application cannot leave you with an archive nobody can open.

Retire is the exit. It is always available and it costs nothing.

## What an auditor should be able to verify

- The `Backup Key Custody` tab lists every provider, its key-custody jurisdiction, its provider domicile, its state, and how many backups depend on it.
- Every create, update, enable, disable, retire, default change, deletion and probe is written to the hash-chained audit log — **including refusals**. An attempt to place the wrapping key in a jurisdiction your policy forbids is itself a recorded event.
- Configuring a provider requires the CISO role, an unlocked configuration state, and a **hardware-passkey step-up**. It is gated exactly as heavily as minting a credential, because it decides who can be compelled to open your backups.
- Credentials are sealed under the GD Tier-1 KEK and are **never returned by a read** — not masked, absent.
- The connection test reads key metadata. It never performs a wrap or an unwrap, so an IAM policy that grants `describe` but not `encrypt` is sufficient to prove reachability.

## Separation from the Management Console

The Regional Server has its own provider registry. The two do not share rows, credentials, allow-lists, or certificate authorities. A provider configured on one server is invisible to the other, and `GD_KMS_ALLOWED_HOSTS` authorises nothing on the Regional Server.

## If a provider becomes unreachable

Backups **fail** rather than silently falling back to `gd-tier1`. An operator who believes the data key is in an HSM must never quietly have it in process memory instead. Fix the provider, or change the default to one that works — the change is prospective and does not alter any archive already written.

If you restore on a host where the recorded scheme is not registered at all, the error says so plainly: the archive is intact, and the module that opens it is missing.
