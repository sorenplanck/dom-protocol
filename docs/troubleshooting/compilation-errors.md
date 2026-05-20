# Compilation Errors

## E0432: Unresolved Import
Add to lib.rs: `pub mod xxx;`

## E0599: Method Not Found
Check actual API: `grep "pub fn" crates/dom-crypto/src/pedersen.rs`

## E0308: Type Mismatch
Match return types between caller and function signature.

## E0277: Trait Bound Not Satisfied
Add derives: `#[derive(Debug, Clone, Serialize, Deserialize)]`

## Strategic Build Order
```bash
cargo build -p dom-core
cargo build -p dom-crypto
cargo build -p dom-consensus
cargo build --all
```
