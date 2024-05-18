# Migrating from Vault Enterprise to OSS

This guide is the result of a lot of work that came from learning the hard way that Vault Enterprise is not necessarily worth the large licensing and support costs that Hashicorp charges, and that with the proper team and configurations, it is quite easy to run reliable and effective Vault clusters. Unless an organization requires FIPS compliance, there is little that Vault Enterprise gives you that cannot be achieved with Vault OSS with a bit of dedication.

The code snippets in this guide are from [https://github.com/nomeelnoj/terraform-aws-vault-cluster](https://github.com/nomeelnoj/terraform-aws-vault-cluster), a Terraform module that works for both Vault OSS and Vault Enterprise.

**NOTE: This guide assumes a running vault cluster on at least 3 ARM-based Ubuntu nodes in AWS, configured by Terraform using an autoscaling group and launch template with `user_data`. Steps will likely be different for other platforms. The vault versions provided by apt have a weird `-1` in the version since 1.9, and some have a `-2`, and sometimes it is before the `+ent` and other times it is after, so make sure to choose the right version for your distribution and architecture (you can use `apt list -a vault-enterprise vault` to find all available versions).

Migrating from Enterprise to OSS is possible, but requires a bit of manual intervention. The reason we cannot do this easily with terraform is because nodes from an OSS cluster cannot join an Enterprise cluster, and vice versa. However, on a running node, you can replace the vault binary and if done properly, you will simply lose access to enterprise features.

If you aim to attempt this migration, please read the entire document carefully and make sure you understand the process.

**NOTE: There are some enterprise features that are enabled by default that will prevent OSS from working properly if not handled correctly. Replacing the binary without first checking for these will result in a Vault that is unable to properly unseal. Please make sure to read [Enterprise Only Features](#enterprise-only-features) below.**

## Warnings and Caveats

This document is meant as a GUIDE only, based on one person's experience. I can make no guarantees that it will work for you as it did for me, and I cannot be held rsponsible if you lose data or your cluster. However, with enough careful planning, I am confident any skilled Vault administrator can complete this migration.

_**TAKE A SNAPSHOT PRIOR TO THE MIGRATION!**_ While an enterprise snapshot cannot be restored to an OSS cluster, a pre-migration snapshot will allow you to start fresh with a new enterprise cluster and try again should anything catastrophic happen, with all the data you had from the time the snapshot was taken.

## Enterprise Only Features

[Vault Enterprise](https://developer.hashicorp.com/vault/docs/enterprise) offers many features that are not available in the OSS version, including but not limited to:

* [Sealwrapping](https://developer.hashicorp.com/vault/docs/enterprise/sealwrap)
* [Automated Raft Snapshots Stored in S3](https://developer.hashicorp.com/vault/docs/enterprise/automated-integrated-storage-snapshots)
* [Namespaces](https://developer.hashicorp.com/vault/docs/enterprise/namespaces)
* [HSM Integration support](https://developer.hashicorp.com/vault/docs/enterprise/hsm)
* [Many others](https://developer.hashicorp.com/vault/docs/enterprise#vault-enterprise) (check the sidebar for a list of enterprise features).

If you are leveraging Vault Enterprise-only features, you will likely need to disable or remove them before you can move to Vault OSS. In most cases, migrating to OSS will simply remove your access to these types of features, but depending on the feature (like Seal Wrap), you may be stuck with an unsealable Vault OSS cluster after migration. Since this document is written based on personal experience, it will only cover how to remove the Enterprise features that were used, rather than include speculation that may not work in actuality.

### Disable Sealwrapping

Vault Enterprise has a feature called [**Seal Wrap**](https://www.vaultproject.io/docs/enterprise/sealwrap). Seal wrap wraps supporting seals in an extra layer of encryption. So, the KMS seal wil be wrapped in an additional layer of encryption that Vault OSS cannot decrypt, resulting in a cluster with data that cannot be decrypted, or "unsealed".

[This module](https://github.com/nomeelnoj/terraform-aws-vault-cluster) disables seal wrapping by default so you should only have to confirm that seal wrapping is disabled by looking at `/etc/vault.d/vault.hcl` and making sure that `disable_sealwrap = true` is set.

However, if seal wrap is enabled and you need to migrate away from OSS, you must first disable it while still licensed for Vault Enterprise:

1. Log into AWS and update the cluster autoscaling group by suspending the processes so it will not replace unhealthy nodes or terminate instances (essentially locking the ASG to the current nodes).
2. SSH into each of the vault servers, and identify the leader, or active node. You can do this with `vault status` on each node, or run `vault operator raft list-peers` from your workstation.
3. On the two **standby nodes**, update the vault config (loaded at runtime so it's ok) and then stop vault:

        echo "disable_sealwrap = true" >> /etc/vault.d/vault.hcl
        systemctl stop vault

4. On the active/leader node, perform almost the same steps, but **restart** vault instead of stopping it.

        echo "disable_sealwrap = true" >> /etc/vault.d/vault.hcl
        systemctl restart vault

5. Immediately go to the other two nodes and start vault back up so that Vault can have a voting quorum.

        systemctl start vault

6. Run `vault status` to ensure that the cluster is healthy. The sealwrap should now show as disabled, so you can replace the enterprise binary with the OSS binary and update the terraform (if you are using it). Specific steps are in the next section.

7. Make sure to go back into AWS and unsuspend the ASG so that the HA and reliability features continue to function.

**IMPORTANT NOTE: Disabling seal wrapping is is a lazy downgrade ([vault docs](https://developer.hashicorp.com/vault/docs/enterprise/sealwrap)); as keys are accessed or written their seal wrapping status will change. If seal wrap is leveraged, after disabling it is prudent to access all seals that were wrapped so they are properly downgraded and the wrap is removed. If this step is not completed, the resulting OSS cluster will be inaccessible.**

### Automated Raft Snapshots

Vault Enterprise includes a nice feature for automating backups called [Automated Integrated Storage Snapshots](https://developer.hashicorp.com/vault/docs/enterprise/automated-integrated-storage-snapshots). This is more of a convenience feature, as achieving daily backups on OSS is relatively straightforward, assuming you have the proper configurations in place. The [terraform object](https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/raft_snapshot_agent_config) that configures the auto-snapshots can be removed--the steps below will show how to accomplish daily snapshots without this object.

#### Creating an Automated Snapshot Workflow

Creating this workflow is actually relatively straightforward, but requires a few extra steps that might not be part of a normal Vault cluster Terraform module or configuration. 
_NOTE: If you use the [linked vault-cluster module](https://github.com/nomeelnoj/terraform-aws-vault-cluster), the snapshot config is included for both OSS and Enterprise deployments, and tthe necessary IAM permissions and S3 buckets will be created with deployment.

In order to automate snapshots, the following items are needed:

1. A vault role that has permissions to take snapshots
2. An AWS IAM role binding for the Vault nodes to be able to authenticate as this role
3. A cronjob script that takes the snapshots and uploads them to S3

Assuming the Vault nodes already have a bound IAM instance profile, we can leverage that along with a Vault role that will allow us to take snapshots.

The snapshot command below requires authentication to Vault, and we only want to run it on the leader/active node. Therefore, we need the above items.

```console
vault operator raft snapshot save > $(date +%Y-%m-%d-%H-%M-%S).snap
```

##### Creating the Resources

First, we need the Vault role. This role will be bound to the IAM principal that is used for the Vault nodes themselves.

**NOTE: The IAM Role associated with the Vault nodes MUST have `s3:PutObject` permissions on the S3 bucket where you intend to store raft snapshots. If the bucket is encrypted with KMS, this role must also be able to use the KMS key to encrypt data uploaded to the bucket.**

The Terraform snippet below will create what is needed:

```hcl
data "vault_policy_document" "snapshotter" {
  rule {
    path         = "/sys/storage/raft/snapshot"
    capabilities = ["read"]
  }
  rule {
    path         = "/sys/storage/raft/configuration"
    capabilities = ["list", "read"]
  }
}

resource "vault_policy" "snapshotter" {
  name   = "snapshotter"
  policy = data.vault_policy_document.snapshotter.hcl
}

resource "vault_aws_auth_backend_role" "snapshotter" {
  backend                  = vault_auth_backend.aws.path
  role                     = "snapshotter"
  auth_type                = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::0123456789:role/vault-cluster-dev"
  token_ttl                = 900
  token_max_ttl            = 900
  token_policies           = [vault_policy.snapshotter.name]
}
```

Once the Vault role itself is configured in Vault and bound to the IAM role on the Vault nodes, it can authenticate using the AWS auth method inside of a cronjob and take regular snapshots and upload them to S3.

The configs needed to template this into the `user_data` correctly are below. Note that `module.backups.bucket` is an S3 module output that represents the name of the S3 bucket we intend to use to store backups. This snippet creates `user_data` for the vault nodes to run at boot and is taken from the recommended [vault module](https://github.com/nomeelnoj/terraform-aws-vault-cluster/blob/main/locals.tf#L45-L69). _**If you are not using this module, your configuration will likely be different**_. The code has to be escaped properly as it is templated through Terraform's `templatefile`, then used in user data to create a cronjob that contains variables. It is highly recommended to test the rendering before migrating to OSS.

```hcl
# locals.tf
locals {
  userdata_values = {
    
    # ... removed for brevity

    snapshot_config = strcontains(
      var.vault_config["vault_version"], "ent"
    ) ? "" : <<EOT
cat <<-EOF > /etc/cron.daily/vault_snapshot
#!/bin/bash

TOKEN=\$(vault login -method=aws -field=token role=snapshotter)

export VAULT_TOKEN="\$${TOKEN}"

IMDS_TOKEN=\$( curl -Ss -H "X-aws-ec2-metadata-token-ttl-seconds: 30" -XPUT 169.254.169.254/latest/api/token )
INSTANCE_ID=\$( curl -Ss -H "X-aws-ec2-metadata-token: \$${IMDS_TOKEN}" 169.254.169.254/latest/meta-data/instance-id )

LEADER_ID=\$(vault operator raft list-peers | grep leader | awk '{print \$1}')

if [[ "\$${INSTANCE_ID}" == "\$${LEADER_ID}" ]]; then
  DATE=\$(date +%Y-%m-%d-%H-%M-%S)
  FILENAME="vault-snapshot-\$${DATE}Z.snap"
  vault operator raft snapshot save \$${FILENAME}
  aws s3 cp "\$${FILENAME}" "s3://${aws_s3_bucket.default.bucket}"
  rm "\$${FILENAME}"
fi
EOF
chmod +x /etc/cron.daily/vault_snapshot
EOT
  }
}
```

This is passed into a `launch_template` as follows:

```hcl
# launch_template.tf
data "cloudinit_config" "user_data" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    filename     = "user_data.sh"
    content      = templatefile("${path.module}/templates/user_data.sh.tpl", local.userdata_values)
  }
}

resource "aws_launch_template" "default" {
  # ... removed for brevity
  user_data = data.cloudinit_config.user_data.rendered
}
```

It is written this way to support both enterprise and OSS deployments, so the above config is optional for the module. For a full example of how it can be used in a functional vault module, make sure to checkout the full [`user_data.sh.tpl`](https://github.com/nomeelnoj/terraform-aws-vault-cluster/blob/main/templates/user_data.sh.tpl) file. The entire snapshot config can be easily passed as a single argument to `templatefile` as shown below. If the templated input is not going to be used with `templatefile`, the escapes will need to be modified.

```sh
${snapshot_config}
```

### Replacing the Enterprise Binary with OSS

_**NOTE: Everything up to this point has been preparation. The following steps outline how to replace the Vault Enterprise binary with the OSS binary. Depending on the enterprise features leveraged, additional preparation is likely required before a migration to OSS is feasible. For example, if the cluster is leveraging namespaces, all secrets must first be moved to the default namespace.**_

It is possible to downgrade from Enterprise to OSS, but has to be done very specifically. If you have not read the section above on [Enterprise Only features](#enterprise-only-featrures), please read it now.

**NOTE: Please read all instructions carefully before taking any action. While this process incurs minimal downtime if done correctly, it should be completed rather quickly, as it takes Vault down to a single node without voters, so with a common voting quorum set to 3 or 5, leader election can fail during this time, causing outages.**

_**MAKE SURE TO TAKE A SNAPSHOT BEFORE STARTING!!!**_

```console
# On the active / leader node
vault login -method=ldap username=jsmith
CURRENT_DATE=$(date -u +%Y-%m-%d-%H-%M-%S)
vault operator raft snapshot save > "pre_oss_migration_${CURRENT_DATE}Z.snap"
aws s3 cp "pre_oss_migration_${CURRENT_DATE}Z.snap" s3://<backups-bucket>
```

1. Log into AWS and suspend the processes on the autoscaling group so that nodes are not replaced when unhealthy or terminated (you can just suspend all the processes, like Terminate, Launch, Replace Unhealthy, etc.), essentially locking the ASG to the current nodes. We are going to be stopping and starting Vault, and it could fail health checks during this time, so we do not want nodes to be replaced while we are working on them.
2. Log into all 3 (or however many you deployed) Vault Enterprise nodes.
3. Use `vault status` on each node to familiarize yourself with "healthy" output and also identify the standby nodes and active node (you can also run `curl -s https://127.0.0.1:8200/v1/sys/leader | jq 'pick(.is_self, .leader_cluster_address)` to find the leader node)
4. On all nodes, download the vault OSS binary using `wget` or `curl` from releases.hashicorp.com. **MAKE SURE TO MATCH THE OS ARCH AND RUNNING ENTERPRISE VERSION!!!**  Make sure you are using the `arm64` binary if running on Graviton!

        VERSION="1.15.4-1"
        ARCH=$(dpkg --print-architecture)
        mkdir -p /tmp/vault
        cd /tmp/vault
        wget "https://releases.hashicorp.com/vault/${VERSION}/vault_${VERSION}_linux_${ARCH}.zip" -O vault.zip

5. Unzip the binaries, but do not move them yet.

        unzip vault.zip

6. On all servers, update the server config file (the linked terraform module defaults to `/etc/vault.d/vault.hcl`, though it may be different in your configuration) and make sure to _**REMOVE**_ the `license_path` line from the file. Save and exit the file. This is safe to do with Vault still running because this file is loaded at runtime.

        sed -i '/license_path/d' /etc/vault.d/vault.hcl
**_NOTE: If you do not remove the `license_path` line from the config file, Vault OSS will not start!!!_**

7. **ON THE STANDBY NODES ONLY:**
    1. Stop vault with `systemctl stop vault`.
    2. This will leave you with a single node cluster, and as long as that node does not attempt a leader election during this time window, Vault should continue to function properly.

8. **ON ALL NODES:**
    1. Replace the binary, making sure to confirm its location first, then make sure to set MLOCK.

            $ which vault
            /usr/bin/vault
            $ mv vault /usr/bin/vault
            $ sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))

9. **ON THE ACTIVE NODE ONLY:**
    1. Restart the vault process to load the new binary and new config that does not have a `license_path` parameter. **IF YOU DO NOT REMOVE THE `license_path` PARAMETER VAULT OSS WILL FAIL TO START!!!**

            # Validate that license_path is not in the config file
            cat /etc/vault.d/vault.hcl | grep 'license_path'
            systemctl restart vault
            vault status

10. After restarting vault on the active node, the `vault status` command should be run to confirm the version that is running and that Vault is unsealed and healthy. If it is not, continue to proceed, as Vault may require a leader election or quorum vote to return to a healthy status.
11. **ON THE STANDBY NODES:** Start vault with

        systemctl start vault
        vault status

12. Confirm that the version running is OSS via `vault status`. The version should _**NOT**_ include `ent` in the name, and the rest of the `vault status` output should look healthy (similar to how it looked at the beginning of this process).
13. On any node or endpoint, log into vault and confirm the cluster members with the operator command:

        vault operator raft list-peers

14. The migration is nearly complete. Unlock the autoscaling group in AWS by removing the suspended processes. Update the terraform to use the OSS binary (remove the +ent from the version) and run `terraform apply`. This will update the `user_data` in the launch template and roll the nodes, so that any future updates or node replacement will function properly and use the OSS binary without a `license_path` parameter:

        vault_binary  = "vault"
        vault_version = "1.15.4-1" # or whatever version, was likely "1.15.4-1+ent" before this work

15. **WARNING!!!** The user data changes made above *SHOULD* configure Vault to take daily snapshots. However it is always a good idea to log into the leader node after Terraform has rolled the nodes and Vault is healthy and run the backup script once manually to validate its functionality and confirm the script functions and all proper permissions are in place.

Thats it--the cluster should now be running Vault OSS! Congratulations! You just saved 100s of 1000s of dollars per year.

## Troubleshooting

Because each vault deployment is unique, this troubleshooting section will not cover all issues that may arise. However, it will attempt to cover some likely issues you may encounter and how to resolve them.

If you have an additional tip you would like to include, please submit a pull request.

#### Cluster does not unseal after migration

Without additional context, it can be difficult to determine why the cluster is not unsealing. One important thing to check is Seal Wrap. If you did not disable seal wrap and access the wrapped seals to lazy downgrade as defined in [Disable Sealwrapping](#disable-sealwrapping) above, the cluster will fail to unseal. However, all is not lost. If your enterprise license is still valid, you can reverse the process described above--add back your license file, update the server configuration file, replace the binary, and restart vault. With the enterprise features restored, it should unseal. You will then be free to disable seal wrapping, lazy downgrade the seals, and try again.

#### No leader - all nodes report as standby

Occasionally a failed leader election during this process can cause an issue like this, though it is rare, and I only saw it in testing, not on any of the 6 production clusters migrated.

If you are left with only standby nodes, make sure to NOT delete the nodes. It is possible that the data has not replicated between raft nodes, so deleting the wrong node may take the data with it. There are a few things to try before starting over from a snapshot:

* Restart `vault` on each node, and wait a minute or two. Sometimes the leader election can take some time.
* Validate the storage size of the raft database, found in ${STORAGE_ROOT}/raft/raft.db. The storage root can be found in the `raft` section of your vault server config file. It will not necesarily be huge, but it should be at least a few MB, possibly much more depending on your Vault usage. If the storage size is not the same on all nodes in the cluster, find the biggest one, and make sure not to delete it, as it likely has the most up to date data.
* Check the operator logs with `journalctl -u vault`. There may be helpful information. If nothing is obvious, you can try a quorum recovery.
* Attempt a [Lost Quorum Recovery](https://developer.hashicorp.com/vault/tutorials/raft/raft-lost-quorum). Start with all nodes in the cluster. If that fails, stop vault on the nodes that DO NOT have the largest raft.db. Follow the instructions for quorum recovery, but only on the one node, and with only one node config in the `raft.json` file. This will essentially tell vault to relaunch as a single-node cluster. You can then restart vault on the standby nodes and a leader election will likely occur, bringing Vault back to a healthy state.

