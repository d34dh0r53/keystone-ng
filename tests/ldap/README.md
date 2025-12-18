# LDAP Backend Tests

Integration tests for the LDAP identity backend implementation.

## Prerequisites

- Running LDAP server on `localhost:1389`
- Test data loaded from `tools/test-data.ldif`

## Setup

Start an LDAP server and load test data:

```bash
# Load test data into LDAP server
ldapadd -x -H ldap://localhost:1389 -D "cn=admin,dc=example,dc=org" \
  -w admin -f tools/test-data.ldif
```

## Running Tests

All LDAP tests are marked with `#[ignore]` since they require a running LDAP server. Use the `--ignored` flag to run them:

```bash
# Run all LDAP tests
cargo test --test ldap -- --ignored

# Run specific test module
cargo test --test ldap user -- --ignored
cargo test --test ldap group -- --ignored
cargo test --test ldap authenticate -- --ignored
cargo test --test ldap user_group -- --ignored

# Run specific test
cargo test --test ldap test_list_users -- --ignored
```

## Test Organization

- `common.rs` - Shared utilities and configuration
- `user.rs` - User CRUD operations (6 tests)
- `group.rs` - Group CRUD operations (6 tests)
- `authenticate.rs` - Password authentication (4 tests)
- `user_group.rs` - User-group membership (4 tests)

## Test Users

The test data includes:

**Users:**
- `alice` (password: `password123`) - member of `admins` and `users`
- `bob` (password: `password123`) - member of `developers` and `users`
- `charlie` (password: `password123`) - member of `users`

**Groups:**
- `admins` - Administrator group
- `developers` - Developer group
- `users` - All users group

## Known Limitations

Write operations (create/update/delete) require LDAP server write permissions and proper configuration. Some tests may be skipped if the server is read-only or misconfigured.
