package it.aboutbits.postgresql.crd.role;

import it.aboutbits.postgresql.core.CRStatus;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

/**
 * Status object for the {@link Role} custom resource.
 * <p>
 * Extends {@link CRStatus} with the {@code metadata.resourceVersion} of the password Secret the
 * operator last applied. This lets the operator detect password changes on clusters where the
 * PostgreSQL verifier in {@code pg_authid} cannot be read (e.g. AWS RDS), so it does not rewrite the
 * password on every reconcile.
 * <p>
 * The stored value is an opaque, non-sensitive Kubernetes resourceVersion. Unlike a password hash,
 * it carries no information about the credential, so exposing it (etcd, backups, {@code get} on the
 * Role CR) does not enable offline password recovery.
 */
@Getter
@Setter
@Accessors(chain = true)
@NullMarked
public class RoleStatus extends CRStatus {
    /**
     * The {@code metadata.resourceVersion} of the {@code passwordSecretRef} Secret at the time the
     * operator last applied the password. {@code null} for roles without a password.
     */
    private @Nullable String appliedPasswordSecretVersion = null;
}
