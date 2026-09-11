package it.aboutbits.postgresql.crd.role;

import it.aboutbits.postgresql.core.SQLUtil;
import it.aboutbits.postgresql.core.infrastructure.persistence.Routines;
import jakarta.inject.Singleton;
import org.jooq.DSLContext;
import org.jooq.Query;
import org.jooq.QueryPart;
import org.jooq.Record1;
import org.jooq.impl.DSL;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Objects;

import static it.aboutbits.postgresql.core.infrastructure.persistence.Tables.PG_AUTH_MEMBERS;
import static it.aboutbits.postgresql.core.infrastructure.persistence.Tables.PG_ROLES;
import static org.jooq.impl.DSL.field;
import static org.jooq.impl.DSL.keyword;
import static org.jooq.impl.DSL.multiset;
import static org.jooq.impl.DSL.query;
import static org.jooq.impl.DSL.role;
import static org.jooq.impl.DSL.select;
import static org.jooq.impl.DSL.selectOne;
import static org.jooq.impl.DSL.sql;
import static org.jooq.impl.DSL.val;

@Singleton
@NullMarked
public final class RoleService {
    public boolean roleExists(
            DSLContext tx,
            RoleSpec spec
    ) {
        return tx.fetchExists(selectOne()
                .from(PG_ROLES)
                .where(PG_ROLES.ROLNAME.eq(spec.getName()))
        );
    }

    public void createRole(
            DSLContext tx,
            RoleSpec spec,
            @Nullable String password
    ) {
        var roleName = spec.getName();
        var flags = spec.getFlags();
        var comment = spec.getComment();

        tx.execute(
                buildCreateRole(
                        roleName,
                        flags,
                        password
                )
        );

        // Optional comment
        if (comment != null && !comment.isBlank()) {
            tx.execute(
                    buildCommentOnRole(roleName, comment)
            );
        }
    }

    public void alterRole(
            DSLContext tx,
            RoleSpec spec,
            RoleSpec.Flags currentFlags,
            boolean changePassword,
            @Nullable String password
    ) {
        var roleName = spec.getName();
        var flags = spec.getFlags();

        tx.execute(
                buildAlterRole(
                        roleName,
                        flags,
                        currentFlags,
                        changePassword,
                        password
                )
        );
    }

    public void updateComment(
            DSLContext tx,
            RoleSpec spec
    ) {
        var roleName = spec.getName();
        var expectedComment = normalizeComment(spec.getComment());

        var currentComment = normalizeComment(
                fetchCurrentRoleComment(tx, roleName)
        );

        if (!Objects.equals(currentComment, expectedComment)) {
            tx.execute(
                    buildCommentOnRole(roleName, expectedComment)
            );
        }
    }

    public boolean roleCommentMatches(
            DSLContext tx,
            RoleSpec spec
    ) {
        var expectedComment = spec.getComment();

        var currentComment = normalizeComment(
                fetchCurrentRoleComment(tx, spec.getName())
        );

        return Objects.equals(currentComment, expectedComment);
    }

    public @Nullable String fetchCurrentRoleComment(
            DSLContext tx,
            String roleName
    ) {

        return tx
                .select(Routines.shobjDescription(
                        PG_ROLES.OID,
                        // Roles live in the pg_authid catalog; shared comments are keyed by that
                        // catalog name even though we read the oid from the pg_roles view.
                        val("pg_authid")
                ))
                .from(PG_ROLES)
                .where(PG_ROLES.ROLNAME.eq(roleName))
                .fetchOneInto(String.class);
    }

    public boolean roleLoginMatches(
            DSLContext tx,
            RoleSpec spec
    ) {
        var loginExpected = spec.getPasswordSecretRef() != null;

        var canLogin = tx.fetchExists(selectOne()
                .from(PG_ROLES)
                .where(PG_ROLES.ROLNAME.eq(spec.getName()))
                .and(PG_ROLES.ROLCANLOGIN.isTrue())
        );

        return loginExpected == canLogin;
    }

    public RoleSpec.Flags fetchCurrentFlags(
            DSLContext tx,
            RoleSpec spec
    ) {
        var member = PG_ROLES.as("member");
        var parent = PG_ROLES.as("parent");

        return tx
                .select(
                        PG_ROLES.ROLSUPER.as("superuser"),
                        PG_ROLES.ROLCREATEDB.as("createdb"),
                        PG_ROLES.ROLCREATEROLE.as("createrole"),
                        PG_ROLES.ROLINHERIT.as("inherit"),
                        PG_ROLES.ROLREPLICATION.as("replication"),
                        PG_ROLES.ROLBYPASSRLS.as("bypassrls"),
                        PG_ROLES.ROLCONNLIMIT.as("connectionLimit"),
                        field("nullif({0}, 'infinity')", PG_ROLES.ROLVALIDUNTIL.getDataType(), PG_ROLES.ROLVALIDUNTIL).as("validUntil"),
                        multiset(
                                select(parent.ROLNAME)
                                        .from(PG_AUTH_MEMBERS)
                                        .join(member).on(member.OID.eq(PG_AUTH_MEMBERS.MEMBER))
                                        .join(parent).on(parent.OID.eq(PG_AUTH_MEMBERS.ROLEID))
                                        .where(member.OID.eq(PG_ROLES.OID))
                                        .orderBy(parent.ROLNAME)
                        ).as("inRole").convertFrom(result -> result.map(Record1::value1)),
                        multiset(
                                select(member.ROLNAME)
                                        .from(PG_AUTH_MEMBERS)
                                        .join(parent).on(parent.OID.eq(PG_AUTH_MEMBERS.ROLEID))
                                        .join(member).on(member.OID.eq(PG_AUTH_MEMBERS.MEMBER))
                                        .where(parent.OID.eq(PG_ROLES.OID))
                                        .orderBy(member.ROLNAME)
                        ).as("role").convertFrom(result -> result.map(Record1::value1))
                )
                .from(PG_ROLES)
                .where(PG_ROLES.ROLNAME.eq(spec.getName()))
                .fetchSingleInto(RoleSpec.Flags.class);
    }

    public void reconcileRoleMembership(
            DSLContext tx,
            RoleSpec spec,
            RoleSpec.Flags expectedFlags,
            RoleSpec.Flags currentFlags
    ) {
        var roleName = spec.getName();

        // ROLE IN
        var expectedInRole = new HashSet<>(expectedFlags.getInRole());
        var currentInRole = new HashSet<>(currentFlags.getInRole());

        var queries = new ArrayList<Query>();

        var inRoleToGrant = new HashSet<>(expectedInRole);
        inRoleToGrant.removeAll(currentInRole);

        var inRoleToRevoke = new HashSet<>(currentInRole);
        inRoleToRevoke.removeAll(expectedInRole);

        for (var parentRole : inRoleToGrant) {
            // GRANT parentRole TO roleName
            queries.add(buildGrantRoleToMember(parentRole, roleName));
        }
        for (var parentRole : inRoleToRevoke) {
            // REVOKE parentRole FROM roleName
            queries.add(buildRevokeRoleFromMember(parentRole, roleName));
        }

        // ROLE
        var expectedRoleMembers = new HashSet<>(expectedFlags.getRole());
        var currentRoleMembers = new HashSet<>(currentFlags.getRole());

        var roleMembersToGrant = new HashSet<>(expectedRoleMembers);
        roleMembersToGrant.removeAll(currentRoleMembers);

        var roleMembersToRevoke = new HashSet<>(currentRoleMembers);
        roleMembersToRevoke.removeAll(expectedRoleMembers);

        for (var member : roleMembersToGrant) {
            // GRANT roleName TO member
            queries.add(buildGrantRoleToMember(roleName, member));
        }
        for (var member : roleMembersToRevoke) {
            // REVOKE roleName FROM member
            queries.add(buildRevokeRoleFromMember(roleName, member));
        }

        if (!queries.isEmpty()) {
            tx.batch(queries).execute();
        }
    }

    public void dropRole(
            DSLContext dsl,
            RoleSpec spec
    ) {
        dsl.execute(
                query("drop role if exists {0}", role(spec.getName()))
        );
    }

    /**
     * Build: CREATE ROLE <name> [ [ WITH ] option [ ... ] ]
     * See <a href="https://www.postgresql.org/docs/current/sql-createrole.html">
     * PostgreSQL: Documentation: CREATE ROLE
     * </a>
     */
    private static Query buildCreateRole(
            String roleName,
            RoleSpec.Flags flags,
            @Nullable String password
    ) {
        var options = new ArrayList<QueryPart>();

        // Only allow the user to log in if a password is specified.
        if (password != null) {
            options.add(keyword(RoleFlag.LOGIN.flag()));
            options.add(keyword(RoleFlag.PASSWORD.flag()));
            options.add(val(password));
        }

        if (flags.isSuperuser()) {
            options.add(keyword(RoleFlag.SUPERUSER.flag()));
        }
        if (flags.isCreatedb()) {
            options.add(keyword(RoleFlag.CREATEDB.flag()));
        }
        if (flags.isCreaterole()) {
            options.add(keyword(RoleFlag.CREATEROLE.flag()));
        }
        if (flags.isInherit()) {
            options.add(keyword(RoleFlag.INHERIT.flag()));
        }
        if (flags.isReplication()) {
            options.add(keyword(RoleFlag.REPLICATION.flag()));
        }
        if (flags.isBypassrls()) {
            options.add(keyword(RoleFlag.BYPASSRLS.flag()));
        }
        if (flags.getConnectionLimit() >= 0) {
            options.add(keyword(RoleFlag.CONNECTION_LIMIT.flag()));
            options.add(val(flags.getConnectionLimit()));
        }

        var validUntil = flags.getValidUntil();
        if (validUntil != null) {
            options.add(keyword(RoleFlag.VALID_UNTIL.flag()));
            options.add(val(validUntil.toString()));
        }

        if (!flags.getInRole().isEmpty()) {
            options.add(keyword(RoleFlag.IN_ROLE.flag()));
            options.add(SQLUtil.concatenateQueryPartsWithComma(
                    flags.getInRole()
                            .stream()
                            .map(DSL::role)
                            .toList()
            ));
        }
        if (!flags.getRole().isEmpty()) {
            options.add(keyword(RoleFlag.ROLE.flag()));
            options.add(SQLUtil.concatenateQueryPartsWithComma(
                    flags.getRole()
                            .stream()
                            .map(DSL::role)
                            .toList()
            ));
        }

        var optionsSql = options.isEmpty()
                ? sql("") // nothing
                : sql(" with {0}", SQLUtil.concatenateQueryPartsWithSpaces(options));

        return query(
                "create role {0}{1}",
                role(roleName),
                optionsSql
        );
    }

    /**
     * Append the token for a privilege-gated role attribute to {@code options} only when the desired
     * value differs from the current one. See {@link #buildAlterRole} for why naming such attributes
     * unconditionally breaks on clusters (e.g. AWS RDS) whose admin is not a superuser.
     */
    private static void addAttributeIfChanged(
            ArrayList<QueryPart> options,
            boolean desired,
            boolean current,
            RoleFlag enabled,
            RoleFlag disabled
    ) {
        if (desired != current) {
            options.add(keyword(desired ? enabled.flag() : disabled.flag()));
        }
    }

    private static Query buildAlterRole(
            String roleName,
            RoleSpec.Flags flags,
            RoleSpec.Flags currentFlags,
            boolean changePassword,
            @Nullable String password
    ) {
        var options = new ArrayList<QueryPart>();
        var loginExpected = password != null;

        // LOGIN / NOLOGIN
        options.add(keyword(loginExpected
                ? RoleFlag.LOGIN.flag()
                : RoleFlag.NO_LOGIN.flag()
        ));

        // Password handling
        // - if NOLOGIN, remove the password
        // - if LOGIN and passwordChanged, set the new password
        if (!loginExpected) {
            options.add(keyword(RoleFlag.PASSWORD.flag()));
            options.add(keyword("NULL"));
        } else if (changePassword) {
            options.add(keyword(RoleFlag.PASSWORD.flag()));
            options.add(val(password));
        }

        // The role attributes below (SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS) are
        // privilege-gated: since PostgreSQL 16, merely *naming* one of these in ALTER ROLE requires
        // the executing role to hold that attribute itself (and only a superuser may name SUPERUSER
        // at all) - even when the value is unchanged. On managed clusters like AWS RDS the admin is
        // not a real superuser, so unconditionally emitting e.g. NOSUPERUSER makes every update fail
        // with "permission denied to alter role". We therefore emit each of these only when it
        // actually differs from the role's current state; a genuine change still (correctly)
        // requires the matching privilege. INHERIT, CONNECTION LIMIT and VALID UNTIL are not
        // privilege-gated and are always safe to assert.
        addAttributeIfChanged(
                options,
                flags.isSuperuser(),
                currentFlags.isSuperuser(),
                RoleFlag.SUPERUSER,
                RoleFlag.NO_SUPERUSER
        );
        addAttributeIfChanged(
                options,
                flags.isCreatedb(),
                currentFlags.isCreatedb(),
                RoleFlag.CREATEDB,
                RoleFlag.NO_CREATEDB
        );
        addAttributeIfChanged(
                options,
                flags.isCreaterole(),
                currentFlags.isCreaterole(),
                RoleFlag.CREATEROLE,
                RoleFlag.NO_CREATEROLE
        );
        addAttributeIfChanged(
                options,
                flags.isReplication(),
                currentFlags.isReplication(),
                RoleFlag.REPLICATION,
                RoleFlag.NO_REPLICATION
        );
        addAttributeIfChanged(
                options,
                flags.isBypassrls(),
                currentFlags.isBypassrls(),
                RoleFlag.BYPASSRLS,
                RoleFlag.NO_BYPASSRLS
        );

        options.add(keyword(flags.isInherit()
                ? RoleFlag.INHERIT.flag()
                : RoleFlag.NO_INHERIT.flag()
        ));

        options.add(keyword(RoleFlag.CONNECTION_LIMIT.flag()));
        options.add(val(flags.getConnectionLimit()));

        var validUntil = flags.getValidUntil();
        options.add(keyword(RoleFlag.VALID_UNTIL.flag()));
        if (validUntil != null) {
            options.add(val(validUntil.toString()));
        } else {
            options.add(val("infinity"));
        }

        return query(
                "alter role {0} with {1}",
                role(roleName),
                SQLUtil.concatenateQueryPartsWithSpaces(options)
        );
    }

    private static Query buildGrantRoleToMember(
            String role,
            String member
    ) {
        return query("grant {0} to {1}", role(role), role(member));
    }

    private static Query buildRevokeRoleFromMember(
            String role,
            String member
    ) {
        return query("revoke {0} from {1}", role(role), role(member));
    }

    /**
     * Build: COMMENT ON ROLE <name> IS <comment>
     */
    private static Query buildCommentOnRole(
            String roleName,
            @Nullable String comment
    ) {
        return query(
                "comment on role {0} is {1}",
                role(roleName),
                val(comment)
        );
    }

    private static @Nullable String normalizeComment(@Nullable String comment) {
        if (comment == null || comment.isBlank()) {
            return null;
        }

        return comment;
    }
}
