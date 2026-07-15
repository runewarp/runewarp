//! Client admission decided once during Config preparation.

/// How the Client wires the **Address controller** at startup.
///
/// Config validation sets this once from Control address presence. Client startup
/// consumes that prepared outcome to choose [`crate::AddressController::for_static`]
/// (seed configured addresses) vs [`crate::AddressController::for_managed`] (empty
/// start + convergence + apply channel) instead of re-deriving mode from `control`
/// at every layer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientAdmission {
    /// Static mode: seed the Address controller from configured Server addresses and
    /// emit the one-shot Client-ready event when first Connected.
    #[default]
    Static,
    /// Managed mode: start with an empty assignment, track Assignment convergence,
    /// and acknowledge applies through the Managed-session adapter.
    Managed,
}
