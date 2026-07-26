use anchor_lang::prelude::*;

#[error_code]
pub enum LiquidatorError {
    #[msg("Caller is not owner")]
    NotOwner,

    #[msg("Caller is not pending owner")]
    NotPendingOwner,

    #[msg("Liquidator is paused")]
    PausedError,

    #[msg("Zero address")]
    ZeroAddress,

    #[msg("Math overflow")]
    MathOverflow,

    // NOTE: appended, never inserted — Anchor derives error codes from variant
    // order (6000 + index), so inserting above would renumber existing errors.
    #[msg("CPI target program does not match the configured perp_engine")]
    InvalidProgram,
}
