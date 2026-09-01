//! Pure model of the Solana escrow lifecycle.

#![forbid(unsafe_code)]

/// Model state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Uninitialized,
    Initialized,
    Funded,
    Claimed,
    Refunded,
    Closed,
}

/// Model event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Initialize,
    Fund,
    ClaimValidSecret,
    ClaimWrongSecret,
    RefundBeforeDeadline,
    RefundAfterDeadline,
    Close,
    Replay,
}

/// Model rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("invalid transition")]
    InvalidTransition,
    #[error("claim secret mismatch")]
    SecretMismatch,
    #[error("refund timelock not reached")]
    Timelock,
    #[error("economic terminal immutable")]
    TerminalImmutable,
}

/// Pure transition.
pub fn transition(state: State, event: Event) -> Result<State, ModelError> {
    use Event as E;
    use State as S;
    if matches!(state, S::Closed) {
        return if event == E::Replay {
            Ok(state)
        } else {
            Err(ModelError::TerminalImmutable)
        };
    }
    match (state, event) {
        (S::Uninitialized, E::Initialize) => Ok(S::Initialized),
        (S::Initialized, E::Fund) => Ok(S::Funded),
        (S::Funded, E::ClaimValidSecret) => Ok(S::Claimed),
        (S::Funded, E::ClaimWrongSecret) => Err(ModelError::SecretMismatch),
        (S::Funded, E::RefundBeforeDeadline) => Err(ModelError::Timelock),
        (S::Funded, E::RefundAfterDeadline) => Ok(S::Refunded),
        (S::Claimed, E::Close) | (S::Refunded, E::Close) => Ok(S::Closed),
        (_, E::Replay) => Ok(state),
        (S::Claimed | S::Refunded, _) => Err(ModelError::TerminalImmutable),
        _ => Err(ModelError::InvalidTransition),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_terminal_is_impossible() {
        let claimed = transition(State::Funded, Event::ClaimValidSecret).unwrap();
        assert_eq!(
            transition(claimed, Event::RefundAfterDeadline),
            Err(ModelError::TerminalImmutable)
        );
    }

    #[test]
    fn refund_requires_deadline() {
        assert_eq!(
            transition(State::Funded, Event::RefundBeforeDeadline),
            Err(ModelError::Timelock)
        );
    }
}
